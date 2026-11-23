// Package clash keeps one selector group of a clash-compatible controller on a
// configured member. It reads the selector, writes only when it has drifted, and
// knows nothing else about clash.
package clash

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/curtisnewbie/miso/errs"
	"github.com/curtisnewbie/miso/miso"
)

const (
	defaultBackoffBase = time.Second
	defaultBackoffMax  = 15 * time.Second
	defaultCycleBudget = time.Minute
	requestTimeout     = 10 * time.Second
)

// Result reports what one managed cycle did.
type Result struct {
	Wrote bool
}

type Client struct {
	controller  string
	secret      string
	selector    string
	proxyName   string
	httpClient  *http.Client
	backoffBase time.Duration
	backoffMax  time.Duration
	budget      time.Duration
}

func New(controller, secret, selector, proxyName string) *Client {
	return &Client{
		controller: strings.TrimRight(controller, "/"),
		secret:     secret,
		selector:   selector,
		proxyName:  proxyName,
		httpClient: &http.Client{
			Timeout: requestTimeout,
			// A redirect is a controller answer, not the operation the caller
			// asked for; following a PUT 302 would turn it into a GET.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		backoffBase: defaultBackoffBase,
		backoffMax:  defaultBackoffMax,
		budget:      defaultCycleBudget,
	}
}

// Run performs one cycle immediately, then one every interval until ctx ends.
func (c *Client) Run(ctx context.Context, interval time.Duration) {
	for {
		res, err := c.Ensure(ctx)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err != nil:
			miso.Warnf("managed clash: %v", err)
		case res.Wrote:
			miso.Infof("managed clash: selector %q now selects %q", c.selector, c.proxyName)
		default:
			miso.Debugf("managed clash: selector %q already selects %q", c.selector, c.proxyName)
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// Ensure runs one bounded cycle: it retries transient failures inside c.budget
// and gives up, leaving the next cycle to try again.
func (c *Client) Ensure(ctx context.Context) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.budget)
	defer cancel()

	delay := c.backoffBase
	for {
		res, transient, err := c.attempt(ctx)
		if err == nil || !transient {
			return res, err
		}

		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Result{}, err
		case <-timer.C:
		}
		if delay < c.backoffMax {
			delay *= 2
			if delay > c.backoffMax {
				delay = c.backoffMax
			}
		}
	}
}

type selectorState struct {
	All []string `json:"all"`
	Now string   `json:"now"`
}

// attempt returns whether the failure is transient (worth retrying).
func (c *Client) attempt(ctx context.Context) (Result, bool, error) {
	state, transient, err := c.readSelector(ctx)
	if err != nil {
		return Result{}, transient, err
	}
	if !slices.Contains(state.All, c.proxyName) {
		return Result{}, false, errs.NewErrf("selector %q has no member %q", c.selector, c.proxyName)
	}
	if state.Now == c.proxyName {
		return Result{}, false, nil
	}

	transient, err = c.selectProxy(ctx)
	if err != nil {
		return Result{}, transient, err
	}
	return Result{Wrote: true}, false, nil
}

func (c *Client) readSelector(ctx context.Context) (selectorState, bool, error) {
	req, err := c.newRequest(ctx, http.MethodGet, c.selector, nil)
	if err != nil {
		return selectorState{}, false, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return selectorState{}, true, errs.Wrapf(err, "read selector %q", c.selector)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return selectorState{}, retryableStatus(resp.StatusCode),
			errs.NewErrf("read selector %q: controller returned status %d", c.selector, resp.StatusCode)
	}

	var state selectorState
	if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
		return selectorState{}, false, errs.Wrapf(err, "read selector %q: decode controller response", c.selector)
	}
	return state, false, nil
}

func (c *Client) selectProxy(ctx context.Context) (bool, error) {
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{c.proxyName})
	if err != nil {
		return false, errs.Wrapf(err, "encode selection for %q", c.selector)
	}
	req, err := c.newRequest(ctx, http.MethodPut, c.selector, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return true, errs.Wrapf(err, "select %q in %q", c.proxyName, c.selector)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return retryableStatus(resp.StatusCode),
			errs.NewErrf("select %q in %q: controller returned status %d", c.proxyName, c.selector, resp.StatusCode)
	}
	return false, nil
}

func (c *Client) newRequest(ctx context.Context, method, name string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.controller+"/proxies/"+url.PathEscape(name), body)
	if err != nil {
		return nil, errs.Wrap(err)
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	return req, nil
}

// retryableStatus is exactly the set a later cycle may fix: the controller is
// unavailable, or homeproxy is not authorized yet. Every other status names a
// wrong controller, selector, or member, or a redirect it must not follow.
func retryableStatus(code int) bool {
	switch {
	case code == http.StatusUnauthorized, code == http.StatusForbidden, code >= 500:
		return true
	}
	return false
}

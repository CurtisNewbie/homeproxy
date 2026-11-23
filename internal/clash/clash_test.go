package clash

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/curtisnewbie/miso/flow"
	"github.com/sirupsen/logrus"
)

type recordedRequest struct {
	method        string
	uri           string
	body          string
	authorization string
	hasAuth       bool
	contentType   string
}

// fakeController is the clash controller contract the client talks to: a GET
// returning one selector's state and a PUT that selects a member.
type fakeController struct {
	server *httptest.Server

	mu        sync.Mutex
	all       []string
	now       string
	getStatus int
	putStatus int
	requests  []recordedRequest
}

func newFakeController(t *testing.T, now string, all ...string) *fakeController {
	t.Helper()

	f := &fakeController{all: all, now: now}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeController) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)

	f.mu.Lock()
	f.requests = append(f.requests, recordedRequest{
		method:        r.Method,
		uri:           r.RequestURI,
		body:          string(body),
		authorization: r.Header.Get("Authorization"),
		hasAuth:       r.Header.Get("Authorization") != "",
		contentType:   r.Header.Get("Content-Type"),
	})
	status := f.putStatus
	if r.Method == http.MethodGet {
		status = f.getStatus
	}
	state := struct {
		Name string   `json:"name"`
		Type string   `json:"type"`
		All  []string `json:"all"`
		Now  string   `json:"now"`
	}{Name: "proxy", Type: "Selector", All: f.all, Now: f.now}
	f.mu.Unlock()

	if status != 0 {
		if status >= 300 && status < 400 {
			w.Header().Set("Location", r.RequestURI)
		}
		w.WriteHeader(status)
		return
	}
	if r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(state)
		return
	}
	var selection struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(body, &selection)
	f.mu.Lock()
	f.now = selection.Name
	f.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (f *fakeController) setStatus(get, put int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getStatus = get
	f.putStatus = put
}

func (f *fakeController) setNow(now string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = now
}

func (f *fakeController) snapshot() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRequest(nil), f.requests...)
}

func (f *fakeController) count(method string) int {
	n := 0
	for _, req := range f.snapshot() {
		if req.method == method {
			n++
		}
	}
	return n
}

func testClient(controller, secret, selector, proxyName string) *Client {
	c := New(controller, secret, selector, proxyName)
	c.backoffBase = time.Millisecond
	c.backoffMax = 5 * time.Millisecond
	c.budget = 100 * time.Millisecond
	return c
}

type logRecord struct {
	level   logrus.Level
	message string
}

type logCapture struct {
	mu      sync.Mutex
	records []logRecord
}

func (l *logCapture) Levels() []logrus.Level {
	return []logrus.Level{logrus.WarnLevel, logrus.InfoLevel}
}

func (l *logCapture) Fire(entry *logrus.Entry) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.records = append(l.records, logRecord{level: entry.Level, message: entry.Message})
	return nil
}

func captureLogs(t *testing.T) *logCapture {
	t.Helper()

	capture := &logCapture{}
	logger := flow.GetLogrusLogger()
	previous := logger.ReplaceHooks(make(logrus.LevelHooks))
	logger.AddHook(capture)
	t.Cleanup(func() { logger.ReplaceHooks(previous) })
	return capture
}

func (l *logCapture) managedClash(level logrus.Level) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var messages []string
	for _, record := range l.records {
		if record.level == level && strings.Contains(record.message, "managed clash") {
			messages = append(messages, record.message)
		}
	}
	return messages
}

func TestEnsureWritesDriftedSelection(t *testing.T) {
	f := newFakeController(t, "a", "a", "b")

	res, err := testClient(f.server.URL, "", "proxy", "b").Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}
	if !res.Wrote {
		t.Error("Wrote = false, want true")
	}

	requests := f.snapshot()
	if len(requests) != 2 {
		t.Fatalf("received %d requests, want 2: %+v", len(requests), requests)
	}
	if requests[0].method != http.MethodGet || requests[0].uri != "/proxies/proxy" {
		t.Errorf("first request = %s %s, want GET /proxies/proxy", requests[0].method, requests[0].uri)
	}
	if requests[1].method != http.MethodPut || requests[1].uri != "/proxies/proxy" {
		t.Errorf("second request = %s %s, want PUT /proxies/proxy", requests[1].method, requests[1].uri)
	}
	if want := `{"name":"b"}`; requests[1].body != want {
		t.Errorf("PUT body = %q, want %q", requests[1].body, want)
	}
	if want := "application/json"; requests[1].contentType != want {
		t.Errorf("PUT Content-Type = %q, want %q", requests[1].contentType, want)
	}
}

func TestEnsureSkipsWriteWhenAlreadySelected(t *testing.T) {
	f := newFakeController(t, "b", "a", "b")

	res, err := testClient(f.server.URL, "", "proxy", "b").Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}
	if res.Wrote {
		t.Error("Wrote = true, want false")
	}
	if puts := f.count(http.MethodPut); puts != 0 {
		t.Errorf("received %d PUTs, want 0", puts)
	}
	if gets := f.count(http.MethodGet); gets != 1 {
		t.Errorf("received %d GETs, want 1", gets)
	}
}

func TestEnsureEscapesNamesIntoThePath(t *testing.T) {
	const selector = "机场/组"
	const proxyName = "香港 🚀"
	f := newFakeController(t, "other", proxyName)

	res, err := testClient(f.server.URL, "", selector, proxyName).Ensure(context.Background())
	if err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}
	if !res.Wrote {
		t.Error("Wrote = false, want true")
	}

	requests := f.snapshot()
	if len(requests) != 2 {
		t.Fatalf("received %d requests, want 2", len(requests))
	}
	const wantURI = "/proxies/%E6%9C%BA%E5%9C%BA%2F%E7%BB%84"
	for _, req := range requests {
		if req.uri != wantURI {
			t.Errorf("%s URI = %q, want %q", req.method, req.uri, wantURI)
		}
	}
	if want := `{"name":"香港 🚀"}`; requests[1].body != want {
		t.Errorf("PUT body = %q, want %q", requests[1].body, want)
	}
}

func TestEnsureSendsBearerOnlyWhenSecretIsSet(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{name: "empty secret sends no header"},
		{name: "set secret sends a bearer header", secret: "s3cret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeController(t, "a", "a", "b")

			if _, err := testClient(f.server.URL, tt.secret, "proxy", "b").Ensure(context.Background()); err != nil {
				t.Fatalf("Ensure() error: %v", err)
			}

			for _, req := range f.snapshot() {
				if tt.secret == "" {
					if req.hasAuth {
						t.Errorf("%s sent Authorization %q with an empty secret", req.method, req.authorization)
					}
					continue
				}
				if want := "Bearer " + tt.secret; req.authorization != want {
					t.Errorf("%s Authorization = %q, want %q", req.method, req.authorization, want)
				}
			}
		})
	}
}

func TestEnsureDoesNotRetryPermanentFailures(t *testing.T) {
	tests := []struct {
		name    string
		getCode int
		putCode int
		now     string
		all     []string
		want    int
	}{
		{name: "selector not found", getCode: http.StatusNotFound, want: 1},
		{name: "selector request rejected", getCode: http.StatusBadRequest, want: 1},
		{name: "selector redirect", getCode: http.StatusFound, want: 1},
		{name: "selector method not allowed", getCode: http.StatusMethodNotAllowed, want: 1},
		{name: "proxy name absent from the group", now: "a", all: []string{"a"}, want: 1},
		{name: "proxy name absent even when now matches", now: "b", all: []string{"a"}, want: 1},
		{name: "selection rejected", now: "a", all: []string{"a", "b"}, putCode: http.StatusNotFound, want: 2},
		{name: "selection redirected", now: "a", all: []string{"a", "b"}, putCode: http.StatusFound, want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeController(t, tt.now, tt.all...)
			f.setStatus(tt.getCode, tt.putCode)

			client := testClient(f.server.URL, "", "proxy", "b")
			start := time.Now()
			res, err := client.Ensure(context.Background())
			if err == nil {
				t.Fatal("Ensure() = nil error, want a permanent failure")
			}
			if res.Wrote {
				t.Error("Wrote = true, want false when the cycle failed")
			}
			if got := len(f.snapshot()); got != tt.want {
				t.Errorf("received %d requests, want %d: %+v", got, tt.want, f.snapshot())
			}
			if elapsed := time.Since(start); elapsed > time.Second {
				t.Errorf("permanent failure took %s, want a prompt return", elapsed)
			}
		})
	}
}

func TestEnsureRetriesTransientFailures(t *testing.T) {
	tests := []struct {
		name    string
		getCode int
		putCode int
		now     string
		all     []string
		method  string
	}{
		{name: "controller error", getCode: http.StatusInternalServerError, method: http.MethodGet},
		{name: "controller unavailable", getCode: http.StatusServiceUnavailable, method: http.MethodGet},
		{name: "unauthorized", getCode: http.StatusUnauthorized, method: http.MethodGet},
		{name: "forbidden", getCode: http.StatusForbidden, method: http.MethodGet},
		{name: "selection temporarily rejected", now: "a", all: []string{"a", "b"}, putCode: http.StatusInternalServerError, method: http.MethodPut},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeController(t, tt.now, tt.all...)
			f.setStatus(tt.getCode, tt.putCode)

			client := testClient(f.server.URL, "", "proxy", "b")
			start := time.Now()
			_, err := client.Ensure(context.Background())
			elapsed := time.Since(start)
			if err == nil {
				t.Fatal("Ensure() = nil error, want a failure after the budget")
			}
			if got := f.count(tt.method); got < 2 {
				t.Errorf("received %d %s requests, want at least 2 retries", got, tt.method)
			}
			if elapsed > time.Second {
				t.Errorf("Ensure() took %s, want it bounded near the 100ms budget", elapsed)
			}
		})
	}
}

func TestEnsureBoundsRetries(t *testing.T) {
	f := newFakeController(t, "a", "a", "b")
	f.setStatus(http.StatusInternalServerError, 0)

	client := testClient(f.server.URL, "", "proxy", "b")
	start := time.Now()
	if _, err := client.Ensure(context.Background()); err == nil {
		t.Fatal("Ensure() = nil error, want a failure after the budget")
	}
	elapsed := time.Since(start)
	if elapsed > time.Second {
		t.Errorf("Ensure() took %s, want it bounded near the 100ms budget", elapsed)
	}
	if got := f.count(http.MethodGet); got > 50 {
		t.Errorf("received %d GETs, want backoff to bound the attempts", got)
	}
}

func TestEnsureStopsRetryingWhenTheContextIsCancelled(t *testing.T) {
	f := newFakeController(t, "a", "a", "b")
	f.setStatus(http.StatusInternalServerError, 0)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := testClient(f.server.URL, "", "proxy", "b").Ensure(ctx); err == nil {
		t.Fatal("Ensure() = nil error, want a cancelled cycle to fail")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("cancelled Ensure() took %s, want a prompt return", elapsed)
	}
}

func TestEnsureReportsAnUnreachableController(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve controller address: %v", err)
	}
	controller := "http://" + ln.Addr().String()
	_ = ln.Close()

	start := time.Now()
	if _, err := testClient(controller, "", "proxy", "b").Ensure(context.Background()); err == nil {
		t.Fatal("Ensure() = nil error, want a transport failure")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("unreachable Ensure() took %s, want it bounded near the 100ms budget", elapsed)
	}
}

func TestRunCorrectsDriftAgainOnTheNextCycle(t *testing.T) {
	f := newFakeController(t, "a", "a", "b")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		testClient(f.server.URL, "", "proxy", "b").Run(ctx, 20*time.Millisecond)
		close(done)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Run did not return after the context was cancelled")
		}
	}()

	waitFor := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("%s did not happen; requests: %+v", what, f.snapshot())
			}
			time.Sleep(5 * time.Millisecond)
		}
	}

	waitFor("the first restoring PUT", func() bool { return f.count(http.MethodPut) == 1 })
	// The first cycle both read and wrote; the second reads the corrected value.
	waitFor("a second cycle GET", func() bool { return f.count(http.MethodGet) >= 2 })
	if puts := f.count(http.MethodPut); puts != 1 {
		t.Fatalf("the second cycle wrote the selection again: %d PUTs, want 1", puts)
	}

	// An external change, as a clash dashboard would make.
	f.setNow("a")
	waitFor("the restoring PUT after the external change", func() bool { return f.count(http.MethodPut) == 2 })
}

func TestRunSurvivesAFailedCycle(t *testing.T) {
	f := newFakeController(t, "a", "a", "b")
	f.setStatus(http.StatusInternalServerError, 0)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		testClient(f.server.URL, "", "proxy", "b").Run(ctx, 20*time.Millisecond)
		close(done)
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("Run did not return after the context was cancelled")
		}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for f.count(http.MethodGet) < 2 {
		if time.Now().After(deadline) {
			t.Fatalf("failed cycle did not retry the GET; requests: %+v", f.snapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Let the failing cycle exhaust its budget, so the next cycle is the one
	// that must recover.
	time.Sleep(150 * time.Millisecond)

	f.setStatus(0, 0)
	deadline = time.Now().Add(3 * time.Second)
	for f.count(http.MethodPut) == 0 {
		if time.Now().After(deadline) {
			t.Fatalf("Run did not recover after a failed cycle; requests: %+v", f.snapshot())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRunWarnsOncePerRedirectedCycle(t *testing.T) {
	tests := []struct {
		name         string
		getCode      int
		putCode      int
		wantRequests int
	}{
		{name: "selector redirect", getCode: http.StatusFound, wantRequests: 1},
		{name: "selection redirect", putCode: http.StatusFound, wantRequests: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFakeController(t, "a", "a", "b")
			f.setStatus(tt.getCode, tt.putCode)
			logs := captureLogs(t)

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				testClient(f.server.URL, "", "proxy", "b").Run(ctx, time.Hour)
				close(done)
			}()

			deadline := time.Now().Add(3 * time.Second)
			for len(logs.managedClash(logrus.WarnLevel)) == 0 {
				if time.Now().After(deadline) {
					cancel()
					t.Fatalf("cycle did not warn; requests: %+v", f.snapshot())
				}
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Run did not return after the context was cancelled")
			}

			if warnings := logs.managedClash(logrus.WarnLevel); len(warnings) != 1 {
				t.Errorf("got %d warnings, want 1: %v", len(warnings), warnings)
			}
			if infos := logs.managedClash(logrus.InfoLevel); len(infos) != 0 {
				t.Errorf("got %d info lines for a failed write, want 0: %v", len(infos), infos)
			}
			if got := len(f.snapshot()); got != tt.wantRequests {
				t.Errorf("received %d requests, want %d: %+v", got, tt.wantRequests, f.snapshot())
			}
		})
	}
}

func TestRunWaitsForTheIntervalBetweenCycles(t *testing.T) {
	f := newFakeController(t, "b", "a", "b") // already correct, so only GETs arrive

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go testClient(f.server.URL, "", "proxy", "b").Run(ctx, 200*time.Millisecond)

	deadline := time.Now().Add(2 * time.Second)
	for f.count(http.MethodGet) == 0 && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if got := f.count(http.MethodGet); got != 1 {
		t.Fatalf("received %d GETs after the startup cycle, want 1", got)
	}

	time.Sleep(50 * time.Millisecond)
	if got := f.count(http.MethodGet); got != 1 {
		t.Errorf("received %d GETs within 50ms of a 200ms interval, want 1", got)
	}

	deadline = time.Now().Add(2 * time.Second)
	for f.count(http.MethodGet) < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := f.count(http.MethodGet); got < 2 {
		t.Errorf("received %d GETs, want the interval to trigger a second cycle", got)
	}
}

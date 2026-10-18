package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/curtisnewbie/homeproxy/internal/config"
	"github.com/curtisnewbie/miso/miso"
)

const (
	proxyAuthChallenge     = `Basic realm="homeproxy"`
	proxyReadHeaderTimeout = 10 * time.Second
	basicAuthPrefix        = "Basic "
)

// errDialFailed marks an outbound dial failure so a request log can name the
// outcome without inspecting the network error. It is matched through the
// transport's error wrapping.
var errDialFailed = errors.New("dial failed")

// upstream is the parsed homeproxy.upstream value. A nil *upstream means direct
// egress; it is parsed once in New so no code path re-reads the config string.
type upstream struct {
	addr          string
	url           *url.URL
	authorization string
}

type Proxy struct {
	cfg       config.Config
	upstream  *upstream
	bypass    bypassList
	resolver  *resolver
	transport *http.Transport
}

func New(cfg config.Config) *Proxy {
	p := &Proxy{cfg: cfg, bypass: newBypassList(cfg.Bypass), resolver: newResolver()}
	if cfg.Upstream != "" {
		p.upstream = &upstream{
			addr: cfg.Upstream,
			url:  &url.URL{Scheme: "http", Host: cfg.Upstream},
		}
		if cfg.UpstreamUsername != "" || cfg.UpstreamPassword != "" {
			// userinfo makes the transport add Proxy-Authorization on forwarded
			// requests; the tunnel path writes the same header itself.
			p.upstream.url.User = url.UserPassword(cfg.UpstreamUsername, cfg.UpstreamPassword)
			p.upstream.authorization = "Basic " + base64.StdEncoding.EncodeToString(
				[]byte(cfg.UpstreamUsername+":"+cfg.UpstreamPassword))
		}
	}
	p.transport = &http.Transport{
		DialContext:        p.dialContext,
		Proxy:              p.proxyURL,
		DisableCompression: true, // a proxy forwards the client's Accept-Encoding instead of negotiating its own
	}
	return p
}

// requestTarget is the authority a request is addressed to, whether the client
// sent an absolute-form request or a CONNECT tunnel.
func requestTarget(r *http.Request) string {
	if r.URL.Host != "" {
		return r.URL.Host
	}
	return r.Host
}

// bypassList is the parsed homeproxy.bypass value, normalized once in New so no
// request path re-reads or re-parses the configured strings.
type bypassList struct {
	hosts    map[string]struct{}
	suffixes []string
}

func newBypassList(entries []string) bypassList {
	list := bypassList{hosts: make(map[string]struct{}, len(entries))}
	for _, entry := range entries {
		entry = hostOnly(entry)
		if entry == "" {
			continue
		}
		if suffix, ok := strings.CutPrefix(entry, "*."); ok {
			if suffix != "" {
				list.suffixes = append(list.suffixes, suffix)
			}
			continue
		}
		list.hosts[entry] = struct{}{}
	}
	return list
}

// matches reports whether target's host is listed. Matching is case-insensitive
// and ignores the port, so "Example.COM:443" matches an "example.com" entry. A
// "*.suffix" entry matches subdomains only; the bare suffix is not a subdomain.
func (b bypassList) matches(target string) bool {
	host := hostOnly(target)
	if _, ok := b.hosts[host]; ok {
		return true
	}
	for _, suffix := range b.suffixes {
		if strings.HasSuffix(host, "."+suffix) {
			return true
		}
	}
	return false
}

// hostOnly reduces an authority to the comparable part of a host name: no port,
// no IPv6 brackets, no trailing dot, lowercase.
func hostOnly(authority string) string {
	authority = strings.TrimSpace(authority)
	if host, _, err := net.SplitHostPort(authority); err == nil {
		authority = host
	}
	authority = strings.TrimPrefix(authority, "[")
	authority = strings.TrimSuffix(authority, "]")
	authority = strings.TrimSuffix(authority, ".")
	return strings.ToLower(authority)
}

// egress is the one egress decision for a target: the upstream to dial through
// (nil means dial the target directly), whether homeproxy.bypass chose the direct
// egress, the addresses the private-network guard vetted, and any reason the
// target must not be reached at all. Tunnels and forwarded requests both use it.
type egress struct {
	upstream *upstream
	bypass   bool
	// addresses are the resolved addresses a direct dial must use. Dialling them
	// instead of the hostname means a second DNS answer cannot redirect the
	// connection after the private-network guard approved it.
	addresses []net.IPAddr
	// refusal is the private-network guard's verdict on a non-bypass host.
	refusal error
	// lookupFailure is a failed host resolution. An upstream, when configured,
	// resolves again itself, so the request is still handed to it; without an
	// upstream there is nothing left to dial.
	lookupFailure error
}

func (e egress) name() string {
	switch {
	case e.refusal != nil:
		return "refused"
	case e.upstream != nil:
		return "upstream"
	case e.lookupFailure != nil:
		return "unresolved"
	default:
		return "direct"
	}
}

// egressContextKey carries the handler's decision to the transport's Proxy and
// DialContext hooks.
type egressContextKey struct{}

func withEgress(ctx context.Context, chosen egress) context.Context {
	return context.WithValue(ctx, egressContextKey{}, chosen)
}

func egressFromContext(ctx context.Context) (egress, bool) {
	chosen, ok := ctx.Value(egressContextKey{}).(egress)
	return chosen, ok
}

// egressFor resolves the target host against homeproxy.bypass, applies the
// private-network guard to every other host, then applies the configured
// upstream. The result is the only place the egress is chosen, and its vetted
// addresses are the ones a direct dial uses.
func (p *Proxy) egressFor(ctx context.Context, target string) egress {
	if p.bypass.matches(target) {
		return egress{bypass: true}
	}

	host := hostOnly(target)
	resolveCtx := ctx
	if p.cfg.DialTimeout > 0 {
		var cancel context.CancelFunc
		resolveCtx, cancel = context.WithTimeout(ctx, p.cfg.DialTimeout)
		defer cancel()
	}
	addresses, err := p.resolver.resolve(resolveCtx, host)
	if err != nil {
		return egress{upstream: p.upstream, lookupFailure: err}
	}
	for _, address := range addresses {
		if nonPublic(address.IP) {
			return egress{refusal: fmt.Errorf("%w: %s resolves to %s", errGuardRefused, host, address.IP)}
		}
	}
	return egress{upstream: p.upstream, addresses: addresses}
}

// proxyURL is the forward half of the single egress decision: the upstream URL
// when the handler chose the upstream egress, nil for a direct dial.
func (p *Proxy) proxyURL(r *http.Request) (*url.URL, error) {
	chosen, ok := egressFromContext(r.Context())
	if !ok {
		return nil, errors.New("proxy: request reached the transport without an egress decision")
	}
	if chosen.upstream == nil {
		return nil, nil
	}
	return chosen.upstream.url, nil
}

// dialContext is the only function that opens outbound connections. Both a
// direct target and the upstream address reach it, so tunnels and forwarded
// requests share the egress decision and the dialler.
func (p *Proxy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	start := time.Now()
	dialer := net.Dialer{Timeout: p.cfg.DialTimeout}
	chosen, ok := egressFromContext(ctx)

	var (
		conn net.Conn
		err  error
	)
	if ok && chosen.upstream == nil && !chosen.bypass && len(chosen.addresses) > 0 {
		conn, err = dialAddresses(ctx, &dialer, network, address, chosen.addresses)
	} else {
		conn, err = dialer.DialContext(ctx, network, address)
	}
	dialDuration.Observe(time.Since(start).Seconds())
	if err != nil {
		dialFailuresTotal.Inc()
		err = fmt.Errorf("%w: %s: %v", errDialFailed, address, err)
	}
	return conn, err
}

// dialAddresses dials the port of address at each vetted IP in turn, keeping the
// port the caller asked for. The dial budget covers the whole attempt.
func dialAddresses(ctx context.Context, dialer *net.Dialer, network, address string, addresses []net.IPAddr) (net.Conn, error) {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	if dialer.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, dialer.Timeout)
		defer cancel()
	}

	var lastErr error
	for _, addr := range addresses {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

// reach opens the connection a CONNECT tunnel runs over, using the egress the
// handler already chose: the direct egress (dialling the vetted addresses when a
// non-bypass host was resolved) or the parsed upstream. A target the
// private-network guard refuses, or an unresolvable one with no upstream to hand
// it to, returns an error before anything is dialled.
func (p *Proxy) reach(ctx context.Context, chosen egress, target string) (net.Conn, error) {
	if chosen.refusal != nil {
		return nil, chosen.refusal
	}
	ctx = withEgress(ctx, chosen)
	if chosen.upstream == nil {
		if chosen.lookupFailure != nil {
			return nil, chosen.lookupFailure
		}
		return p.dialContext(ctx, "tcp", target)
	}
	return p.dialUpstream(ctx, chosen.upstream, target)
}

// dialUpstream dials the upstream and asks it for a tunnel to target.
// Any bytes the upstream sent after its status line stay readable from the
// returned connection.
func (p *Proxy) dialUpstream(ctx context.Context, upstream *upstream, target string) (net.Conn, error) {
	// One budget covers dialling and the CONNECT handshake together.
	var deadline time.Time
	if p.cfg.DialTimeout > 0 {
		deadline = time.Now().Add(p.cfg.DialTimeout)
	}

	conn, err := p.dialContext(ctx, "tcp", upstream.addr)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		_ = conn.Close()
		return nil, err
	}

	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
	}

	reader := bufio.NewReader(conn)
	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if upstream.authorization != "" {
		fmt.Fprintf(&request, "Proxy-Authorization: %s\r\n", upstream.authorization)
	}
	request.WriteString("\r\n")
	if _, err := io.WriteString(conn, request.String()); err != nil {
		return fail(err)
	}

	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return fail(err)
	}
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("upstream refused CONNECT to %s: %s", target, resp.Status))
	}

	// The handshake is over: a tunnel carries long-lived traffic and has no idle
	// timeout, so the dial deadline must not survive into it.
	if !deadline.IsZero() {
		_ = conn.SetDeadline(time.Time{})
	}

	return &upstreamConn{Conn: conn, reader: reader}, nil
}

// upstreamConn reads through the bufio.Reader the CONNECT response was parsed
// from, so a fast upstream cannot lose bytes it sent behind the status line.
type upstreamConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *upstreamConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (c *upstreamConn) CloseWrite() error {
	closeWrite(c.Conn)
	return nil
}

func Serve(ln net.Listener, cfg config.Config) *http.Server {
	srv := &http.Server{
		Handler:           New(cfg),
		ReadHeaderTimeout: proxyReadHeaderTimeout,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			miso.Errorf("proxy server stopped: %v", err)
		}
	}()
	return srv
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestsTotal.Inc()
	auth := p.authenticate(r)
	if !auth.ok {
		authFailuresTotal.Inc()
		miso.Warnf("proxy auth failed remote=%s name=%q", r.RemoteAddr, auth.attempted)
		writeAuthChallenge(w)
		return
	}

	if r.Method == http.MethodConnect {
		p.tunnel(w, r, auth.name)
		return
	}

	p.forward(w, r, auth.name)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, credential string) {
	start := time.Now()
	target := requestTarget(r)

	var (
		up      atomic.Int64
		down    atomic.Int64
		counted bool
		outcome string
		failure error
		chosen  egress
		decided bool
	)
	defer func() {
		if counted {
			bytesUpTotal.Add(float64(up.Load()))
			bytesDownTotal.Add(float64(down.Load()))
		}
		egressName, bypass := "undecided", false
		if decided {
			egressName, bypass = chosen.name(), chosen.bypass
		}
		if failure != nil {
			miso.Errorf("proxy request credential=%s target=%s egress=%s bypass=%t up=%d down=%d duration=%s outcome=%s error=%v",
				credential, target, egressName, bypass, up.Load(), down.Load(), time.Since(start), outcome, failure)
			return
		}
		miso.Infof("proxy request credential=%s target=%s egress=%s bypass=%t up=%d down=%d duration=%s outcome=%s",
			credential, target, egressName, bypass, up.Load(), down.Load(), time.Since(start), outcome)
	}()

	// The request's Host is client-controlled, so it is validated before it can
	// trigger a resolution for a request that is answered without one.
	if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.Host == "" {
		outcome = strconv.Itoa(http.StatusBadRequest)
		writeStatus(w, http.StatusBadRequest)
		return
	}

	chosen = p.egressFor(r.Context(), target)
	decided = true

	// The private-network guard runs before the request reaches the transport, so
	// neither the upstream nor the target sees a refused request.
	if chosen.refusal != nil {
		failure = chosen.refusal
		outcome = "forbidden"
		writeStatus(w, http.StatusForbidden)
		return
	}

	// A failed lookup leaves nothing to dial when no upstream is configured; the
	// upstream resolves the host again itself, so it is used when it exists.
	if chosen.lookupFailure != nil && chosen.upstream == nil {
		failure = chosen.lookupFailure
		outcome = "lookup-failed"
		writeStatus(w, http.StatusBadGateway)
		return
	}

	outreq := r.Clone(withEgress(r.Context(), chosen))
	outreq.RequestURI = ""
	outreq.Host = r.URL.Host
	stripHopByHop(outreq.Header)
	if outreq.Body != nil {
		outreq.Body = &countingBody{ReadCloser: outreq.Body, count: &up}
	}

	resp, err := p.transport.RoundTrip(outreq)
	// The transport may have read the request body even when it failed, and a
	// failed RoundTrip still attempted a dial, so these bytes belong to the request.
	counted = true
	if err != nil {
		// The failure belongs to this request: report it and keep serving.
		failure = err
		outcome = strconv.Itoa(http.StatusBadGateway)
		if errors.Is(err, errDialFailed) {
			outcome = "dial-failed"
		}
		writeStatus(w, http.StatusBadGateway)
		return
	}

	// A 407 from a configured upstream rejects homeproxy's own credentials, not
	// the client's: it must not masquerade as the client's auth challenge. The
	// tunnel path already treats it as a gateway failure.
	if chosen.upstream != nil && resp.StatusCode == http.StatusProxyAuthRequired {
		resp.Body.Close()
		failure = fmt.Errorf("upstream rejected credentials: %s", resp.Status)
		outcome = strconv.Itoa(http.StatusBadGateway)
		writeStatus(w, http.StatusBadGateway)
		return
	}

	resp.Body = &countingBody{ReadCloser: resp.Body, count: &down}
	defer resp.Body.Close()

	stripHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	outcome = strconv.Itoa(resp.StatusCode)
	w.WriteHeader(resp.StatusCode)
	if err := streamBody(w, resp.Body); err != nil {
		outcome = "aborted"
		failure = err
		// The headers are already sent, so the only honest signal left is to abort
		// the connection instead of ending the body as if it were complete.
		panic(http.ErrAbortHandler)
	}
}

// countingBody records how many bytes were read through it, so a forwarded
// request and response report the bytes that actually crossed the wire.
type countingBody struct {
	io.ReadCloser
	count *atomic.Int64
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.count.Add(int64(n))
	return n, err
}

// streamBody copies the response as it arrives and flushes after every chunk, so a
// slow target is delivered incrementally rather than buffered to completion. It
// returns the read, write or flush failure that stopped the stream.
func streamBody(w http.ResponseWriter, body io.Reader) error {
	controller := http.NewResponseController(w)
	buf := make([]byte, 32*1024)
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				// The client is gone; there is nobody left to answer.
				return writeErr
			}
			if err := controller.Flush(); err != nil {
				return err
			}
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			return nil
		}
		return readErr
	}
}

// hopByHopHeaders are meaningful for one connection only; a proxy consumes them
// instead of passing them on.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"TE",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// stripHopByHop removes the standard hop-by-hop headers plus every header named by
// the Connection token list (RFC 7230 section 6.1).
func stripHopByHop(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				h.Del(token)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

func copyHeader(dst, src http.Header) {
	for name, values := range src {
		for _, value := range values {
			dst.Add(name, value)
		}
	}
}

func writeAuthChallenge(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", proxyAuthChallenge)
	writeStatus(w, http.StatusProxyAuthRequired)
}

func writeStatus(w http.ResponseWriter, status int) {
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(status)
}

// authentication is the outcome of one Proxy-Authorization attempt. attempted
// always carries the decoded name part when the header decodes, so an auth
// failure can name who tried; name is only set for a successful match.
type authentication struct {
	name      string
	attempted string
	ok        bool
}

// authenticate reports whether the request carries a configured credential.
// Missing, malformed, unknown-name and wrong-secret credentials all take the same
// false path; names and secrets are compared as fixed-size digests in constant
// time so the rejection never reveals which part was wrong.
func (p *Proxy) authenticate(r *http.Request) authentication {
	header := r.Header.Get("Proxy-Authorization")
	if len(header) < len(basicAuthPrefix) || !strings.EqualFold(header[:len(basicAuthPrefix)], basicAuthPrefix) {
		return authentication{}
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(basicAuthPrefix):]))
	if err != nil {
		return authentication{}
	}
	name, secret, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return authentication{}
	}
	auth := authentication{attempted: name}

	nameDigest := sha256.Sum256([]byte(name))
	secretDigest := sha256.Sum256([]byte(secret))
	matched := 0
	for _, credential := range p.cfg.Credentials {
		credentialName := sha256.Sum256([]byte(credential.Name))
		credentialSecret := sha256.Sum256([]byte(credential.Secret))
		nameMatches := subtle.ConstantTimeCompare(nameDigest[:], credentialName[:])
		secretMatches := subtle.ConstantTimeCompare(secretDigest[:], credentialSecret[:])
		hit := nameMatches & secretMatches
		if hit == 1 {
			auth.name = credential.Name
		}
		matched |= hit
	}
	auth.ok = matched == 1
	if !auth.ok {
		auth.name = ""
	}
	return auth
}

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request, credential string) {
	start := time.Now()
	chosen := p.egressFor(r.Context(), r.Host)
	var (
		up      int64
		down    int64
		outcome = "ok"
	)

	target, err := p.reach(r.Context(), chosen, r.Host)
	if err != nil {
		// Still on the normal HTTP path: report the failure without opening a tunnel.
		// A policy refusal, a failed lookup and a failed dial are different outcomes.
		outcome := "dial-failed"
		status := http.StatusBadGateway
		switch {
		case errors.Is(err, errGuardRefused):
			outcome = "forbidden"
			status = http.StatusForbidden
		case chosen.upstream == nil && chosen.lookupFailure != nil:
			outcome = "lookup-failed"
		}
		miso.Errorf("proxy tunnel failed credential=%s target=%s egress=%s bypass=%t duration=%s outcome=%s error=%v",
			credential, r.Host, chosen.name(), chosen.bypass, time.Since(start), outcome, err)
		writeStatus(w, status)
		return
	}
	defer target.Close()
	defer func() {
		miso.Infof("proxy tunnel credential=%s target=%s egress=%s bypass=%t up=%d down=%d duration=%s outcome=%s",
			credential, r.Host, chosen.name(), chosen.bypass, up, down, time.Since(start), outcome)
	}()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		outcome = "hijack-failed"
		http.Error(w, "proxy does not support hijacking", http.StatusInternalServerError)
		return
	}
	client, clientBuffer, err := hijacker.Hijack()
	if err != nil {
		outcome = "hijack-failed"
		return
	}
	defer client.Close()

	if _, err := clientBuffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		outcome = "handshake-failed"
		return
	}
	if err := clientBuffer.Flush(); err != nil {
		outcome = "handshake-failed"
		return
	}

	tunnelsActive.Inc()
	defer tunnelsActive.Dec()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		up, _ = io.Copy(target, clientBuffer.Reader)
		// The client finished sending: signal EOF to the target but keep reading the
		// reverse direction so a half-closed request can still receive its response.
		closeWrite(target)
	}()
	go func() {
		defer wg.Done()
		down, _ = io.Copy(client, target)
		// The target ended, so no bytes can flow back to the client any more. Close
		// the client fully: this unblocks the surviving client->target copy instead of
		// leaving it parked on a read that will never finish. A client that only
		// half-closed its write side still took the other branch, so its request
		// reaches the target and the reply above was already delivered in full.
		_ = client.Close()
	}()
	wg.Wait()

	bytesUpTotal.Add(float64(up))
	bytesDownTotal.Add(float64(down))
}

type closeWriter interface {
	CloseWrite() error
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
		return
	}
	_ = conn.Close()
}

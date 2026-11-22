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
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/curtisnewbie/homeproxy/internal/config"
	"github.com/curtisnewbie/miso/flow"
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
	pac       pac
	trusted   trustedList
	resolver  *resolver
	transport *http.Transport
}

func New(cfg config.Config) *Proxy {
	if cfg.PACRequireTrustedClient && len(cfg.TrustedClients) == 0 {
		miso.Warnf("homeproxy.pac.require-trusted-client is on but homeproxy.trusted-clients is empty: /proxy.pac is served to nobody")
	}
	p := &Proxy{cfg: cfg, bypass: newBypassList(cfg.Bypass), pac: newPAC(cfg.PACMode, cfg.PACDirect, cfg.PACProxyHosts), trusted: newTrustedList(cfg.TrustedClients), resolver: newResolver()}
	if key, ignored := p.pac.ignoredList(); ignored {
		miso.Warnf("%s has entries but homeproxy.pac.mode is %s: the list is ignored", key, p.pac.mode)
	}
	// Only an upstream that exists can be dead; without one, egress pac changes
	// nothing to warn about.
	if cfg.Upstream != "" && cfg.UpstreamEgress == config.UpstreamEgressPAC &&
		p.pac.mode == config.PACModeDirect && p.pac.proxyHosts.empty() {
		miso.Warnf("homeproxy.upstream.egress is pac but homeproxy.pac.mode is direct and homeproxy.pac.proxy-hosts is empty: the upstream can never be used")
	}
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
		entry = config.HostOnly(entry)
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
	host := config.HostOnly(target)
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

func (b bypassList) empty() bool {
	return len(b.hosts) == 0 && len(b.suffixes) == 0
}

// pacCacheLifetime bounds how long a client may reuse a PAC it already fetched.
// CFNetwork reads only Expires and otherwise caches for 24 hours, so this is the
// whole cache policy. Keep it short: a stale file keeps routing by an old host
// list for its whole lifetime.
const pacCacheLifetime = time.Minute

// pac renders the Proxy Auto-Configuration file served at /proxy.pac. Only the
// mode's own list is consulted; the other is parsed but never emitted.
type pac struct {
	mode       string
	direct     bypassList
	proxyHosts bypassList
}

func newPAC(mode string, direct, proxyHosts []string) pac {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode != config.PACModeProxy {
		mode = config.PACModeDirect
	}
	return pac{mode: mode, direct: newBypassList(direct), proxyHosts: newBypassList(proxyHosts)}
}

// ignoredList names the list the active mode does not consult, when it has
// entries the operator will not see take effect.
func (p pac) ignoredList() (string, bool) {
	if p.mode == config.PACModeProxy {
		return config.KeyPACProxyHosts, !p.proxyHosts.empty()
	}
	return config.KeyPACDirect, !p.direct.empty()
}

// proxies reports whether the PAC file routes target through the proxy. It
// mirrors script exactly: the active mode's own list decides, and a listed entry
// is what the mode assigns to the proxy.
func (p pac) proxies(target string) bool {
	if p.mode == config.PACModeProxy {
		return !p.direct.matches(target)
	}
	return p.proxyHosts.matches(target)
}

// script renders the file for one proxy token. The entries were validated at
// load and normalized in newBypassList, so the body carries only normalized
// values.
func (p pac) script(proxy string) string {
	var b strings.Builder
	b.WriteString("function FindProxyForURL(url, host) {\n")
	b.WriteString("  host = host.toLowerCase();\n")
	// A client passes an IPv6 literal bracketed; the entries are not, because
	// the list went through HostOnly.
	b.WriteString("  if (host.charAt(0) === \"[\") { host = host.slice(1, -1); }\n")
	entries, listed, unlisted := p.proxyHosts, "PROXY "+proxy+"; DIRECT", "DIRECT"
	if p.mode == config.PACModeProxy {
		entries, listed, unlisted = p.direct, "DIRECT", "PROXY "+proxy+"; DIRECT"
	}
	hosts := make([]string, 0, len(entries.hosts))
	for host := range entries.hosts {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	for _, host := range hosts {
		fmt.Fprintf(&b, "  if (host === %s) { return %s; }\n", jsString(host), jsString(listed))
	}
	for _, suffix := range entries.suffixes {
		// The leading dot and the strict length leave the bare suffix unmatched,
		// exactly like bypassList.matches.
		fmt.Fprintf(&b, "  if (host.length > %d && host.slice(-%d) === %s) { return %s; }\n",
			len(suffix)+1, len(suffix)+1, jsString("."+suffix), jsString(listed))
	}
	fmt.Fprintf(&b, "  return %s;\n", jsString(unlisted))
	b.WriteString("}\n")
	return b.String()
}

// jsString renders s as a JavaScript double-quoted string literal. The inputs
// are character-restricted, so escaping the quote and the escape character is
// enough; a Go literal (%q) would emit escapes JavaScript does not know.
func jsString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// trustedList is the parsed homeproxy.trusted-clients value, parsed once in New
// so no request path re-reads or re-parses the configured strings.
type trustedList []netip.Prefix

func newTrustedList(entries []string) trustedList {
	prefixes, err := config.ParseTrustedClients(entries)
	if err != nil {
		// Load validates the list before a Config reaches here; a hand-built
		// Config with a bad entry trusts nothing.
		miso.Warnf("homeproxy.trusted-clients ignored: %v", err)
		return nil
	}
	return prefixes
}

// match reports whether remoteAddr belongs to a trusted client. It uses the
// host part of the connection's address and nothing else: no header, no DNS. An
// IPv4-mapped IPv6 address is unmapped so it matches an IPv4 entry.
func (t trustedList) match(remoteAddr string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(config.HostOnly(remoteAddr))
	if err != nil {
		return netip.Addr{}, false
	}
	addr = addr.WithZone("")
	addr = addr.Unmap()
	for _, prefix := range t {
		if prefix.Contains(addr) {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// clientIdentity is what a request log names: the credential that authorized the
// request, or the trusted address that stood in for one.
type clientIdentity struct {
	credential string
	trusted    bool
}

// logFields renders the identity fields of a request log line. A trusted request
// adds trusted=true; an untrusted one keeps the shape it had before trust existed.
func (c clientIdentity) logFields() string {
	if !c.trusted {
		return "credential=" + c.credential
	}
	return "credential=" + c.credential + " trusted=true"
}

// trustedToken renders a client address inside the trusted credential field. An
// IPv6 address is bracketed so the token stays parseable; IPv4 stays plain.
func trustedToken(addr netip.Addr) string {
	if addr.Is6() {
		return "[" + addr.String() + "]"
	}
	return addr.String()
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

	host := config.HostOnly(target)
	resolveCtx := ctx
	if p.cfg.DialTimeout > 0 {
		var cancel context.CancelFunc
		resolveCtx, cancel = context.WithTimeout(ctx, p.cfg.DialTimeout)
		defer cancel()
	}
	addresses, err := p.resolver.resolve(resolveCtx, host)
	if err != nil {
		// Without an upstream a failed lookup leaves nothing to dial. With
		// egress pac, a PAC-direct target is in the same position even when an
		// upstream exists, because that upstream is not for this target.
		if p.cfg.UpstreamEgress == config.UpstreamEgressPAC && !p.pac.proxies(target) {
			return egress{lookupFailure: err}
		}
		return egress{upstream: p.upstream, lookupFailure: err}
	}
	for _, address := range addresses {
		if nonPublic(address.IP) {
			return egress{refusal: fmt.Errorf("%w: %s resolves to %s", errGuardRefused, host, address.IP)}
		}
	}
	// The guard has vetted the addresses. Egress pac keeps the upstream only for
	// the targets the PAC routes through the proxy; the rest use the direct egress
	// at these same addresses.
	if p.cfg.UpstreamEgress == config.UpstreamEgressPAC && !p.pac.proxies(target) {
		return egress{addresses: addresses}
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
	// A PAC fetch is origin-form; proxied traffic arrives absolute-form or as
	// CONNECT, so the two can never mean the same request.
	if r.Method == http.MethodGet && !r.URL.IsAbs() && r.URL.Path == "/proxy.pac" {
		p.servePAC(w, r)
		return
	}
	auth := p.authenticate(r)
	trustedAddr, trusted := p.trusted.match(r.RemoteAddr)
	if !auth.ok && !trusted {
		authFailuresTotal.Inc()
		// Info, not Debug: a client in automatic mode sends no credential, so a
		// refusal here is the whole reason a PAC file appears to be ignored.
		miso.Infof("proxy auth failed remote=%s name=%q", r.RemoteAddr, auth.attempted)
		writeAuthChallenge(w)
		return
	}

	identity := clientIdentity{credential: auth.name, trusted: trusted}
	if !auth.ok {
		identity.credential = "trusted:" + trustedToken(trustedAddr)
	}

	if r.Method == http.MethodConnect {
		p.tunnel(w, r, identity)
		return
	}

	p.forward(w, r, identity)
}

// servePAC writes the generated PAC file. It runs before authentication because
// iOS sends no credential in automatic mode; the file is public unless
// homeproxy.pac.require-trusted-client restricts it to the trusted address list.
func (p *Proxy) servePAC(w http.ResponseWriter, r *http.Request) {
	if p.cfg.PACRequireTrustedClient {
		if _, trusted := p.trusted.match(r.RemoteAddr); !trusted {
			flow.Infof("Forbidden, %v", r.RemoteAddr)
			writeStatus(w, http.StatusForbidden)
			return
		}
	}
	proxyAddr := p.cfg.PACProxy
	if proxyAddr == "" {
		host := config.HostOnly(r.Host)
		if !config.ValidHost(host) {
			writeStatus(w, http.StatusBadRequest)
			return
		}
		proxyAddr = net.JoinHostPort(host, strconv.Itoa(p.cfg.ProxyPort))
	} else if host, port, err := net.SplitHostPort(proxyAddr); err == nil {
		// Load validated the address; the port is re-emitted as its number so a
		// leading zero or sign cannot make the client reject the file.
		if number, err := strconv.Atoi(port); err == nil {
			proxyAddr = net.JoinHostPort(host, strconv.Itoa(number))
		}
	}
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	w.Header().Set("Cache-Control", "no-store")
	// CFNetwork ignores Cache-Control and honours only Expires, defaulting to a
	// 24-hour cache when the header is absent. Five minutes keeps a config edit
	// visible quickly while a still-fresh entry survives a transient failure to
	// fetch the file, which would otherwise drop the client to DIRECT.
	w.Header().Set("Expires", time.Now().Add(pacCacheLifetime).UTC().Format(http.TimeFormat))
	// Info, so the box shows whether the client ever fetched the file: a PAC the
	// client never loads and a PAC it loads but ignores look identical from the
	// proxy, because neither produces a request log line.
	miso.Infof("pac served remote=%s host=%s proxy=%s", r.RemoteAddr, r.Host, proxyAddr)
	_, _ = io.WriteString(w, p.pac.script(proxyAddr))
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, identity clientIdentity) {
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
			miso.Errorf("proxy request %s target=%s egress=%s bypass=%t up=%d down=%d duration=%s outcome=%s error=%v",
				identity.logFields(), target, egressName, bypass, up.Load(), down.Load(), time.Since(start), outcome, failure)
			return
		}
		miso.Infof("proxy request %s target=%s egress=%s bypass=%t up=%d down=%d duration=%s outcome=%s",
			identity.logFields(), target, egressName, bypass, up.Load(), down.Load(), time.Since(start), outcome)
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

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request, identity clientIdentity) {
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
		miso.Errorf("proxy tunnel failed %s target=%s egress=%s bypass=%t duration=%s outcome=%s error=%v",
			identity.logFields(), r.Host, chosen.name(), chosen.bypass, time.Since(start), outcome, err)
		writeStatus(w, status)
		return
	}
	defer target.Close()
	defer func() {
		miso.Infof("proxy tunnel %s target=%s egress=%s bypass=%t up=%d down=%d duration=%s outcome=%s",
			identity.logFields(), r.Host, chosen.name(), chosen.bypass, up, down, time.Since(start), outcome)
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

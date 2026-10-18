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
	"strings"
	"sync"
	"time"

	"github.com/curtisnewbie/homeproxy/internal/config"
	"github.com/curtisnewbie/miso/miso"
)

const (
	proxyAuthChallenge     = `Basic realm="homeproxy"`
	proxyReadHeaderTimeout = 10 * time.Second
	basicAuthPrefix        = "Basic "
)

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
	transport *http.Transport
}

func New(cfg config.Config) *Proxy {
	p := &Proxy{cfg: cfg}
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

// proxyURL is the forward half of the single egress decision: the upstream URL
// when one is configured, nil for a direct dial of the request's target.
func (p *Proxy) proxyURL(*http.Request) (*url.URL, error) {
	if p.upstream == nil {
		return nil, nil
	}
	return p.upstream.url, nil
}

// dialContext is the only function that opens outbound connections. The one
// parsed upstream value decides the address it is given (the upstream when
// configured, the target otherwise), so tunnels and forwarded requests share
// both the egress decision and the dialler.
func (p *Proxy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: p.cfg.DialTimeout}
	return dialer.DialContext(ctx, network, address)
}

// reach opens the connection a CONNECT tunnel runs over. It is the tunnel half of
// the single egress decision: the parsed upstream or a direct dial of the target.
func (p *Proxy) reach(ctx context.Context, target string) (net.Conn, error) {
	if p.upstream == nil {
		return p.dialContext(ctx, "tcp", target)
	}
	return p.dialUpstream(ctx, target)
}

// dialUpstream dials the configured upstream and asks it for a tunnel to target.
// Any bytes the upstream sent after its status line stay readable from the
// returned connection.
func (p *Proxy) dialUpstream(ctx context.Context, target string) (net.Conn, error) {
	// One budget covers dialling and the CONNECT handshake together.
	var deadline time.Time
	if p.cfg.DialTimeout > 0 {
		deadline = time.Now().Add(p.cfg.DialTimeout)
	}

	conn, err := p.dialContext(ctx, "tcp", p.upstream.addr)
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
	if p.upstream.authorization != "" {
		fmt.Fprintf(&request, "Proxy-Authorization: %s\r\n", p.upstream.authorization)
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
	if !p.authorized(r) {
		writeAuthChallenge(w)
		return
	}

	if r.Method == http.MethodConnect {
		p.tunnel(w, r)
		return
	}

	p.forward(w, r)
}

func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	if !r.URL.IsAbs() || r.URL.Scheme != "http" || r.URL.Host == "" {
		writeStatus(w, http.StatusBadRequest)
		return
	}

	outreq := r.Clone(r.Context())
	outreq.RequestURI = ""
	outreq.Host = r.URL.Host
	stripHopByHop(outreq.Header)

	resp, err := p.transport.RoundTrip(outreq)
	if err != nil {
		// The failure belongs to this request: report it and keep serving.
		miso.Errorf("proxy cannot forward to %s: %v", r.URL.Host, err)
		writeStatus(w, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// A 407 from a configured upstream rejects homeproxy's own credentials, not
	// the client's: it must not masquerade as the client's auth challenge. The
	// tunnel path already treats it as a gateway failure.
	if p.upstream != nil && resp.StatusCode == http.StatusProxyAuthRequired {
		miso.Errorf("upstream rejected credentials for %s: %s", r.URL.Host, resp.Status)
		writeStatus(w, http.StatusBadGateway)
		return
	}

	stripHopByHop(resp.Header)
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	streamBody(w, resp.Body)
}

// streamBody copies the response as it arrives and flushes after every chunk, so a
// slow target is delivered incrementally rather than buffered to completion.
func streamBody(w http.ResponseWriter, body io.Reader) {
	controller := http.NewResponseController(w)
	buf := make([]byte, 32*1024)
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			if _, writeErr := w.Write(buf[:n]); writeErr != nil {
				// The client is gone; there is nobody left to answer.
				return
			}
			if err := controller.Flush(); err != nil {
				return
			}
		}
		if readErr == nil {
			continue
		}
		if errors.Is(readErr, io.EOF) {
			return
		}
		// The headers are already sent, so the only honest signal left is to abort
		// the connection instead of ending the body as if it were complete.
		panic(http.ErrAbortHandler)
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

// authorized reports whether the request carries a configured credential. Missing,
// malformed, unknown-name and wrong-secret credentials all take the same false path;
// names and secrets are compared as fixed-size digests in constant time so the
// rejection never reveals which part was wrong.
func (p *Proxy) authorized(r *http.Request) bool {
	header := r.Header.Get("Proxy-Authorization")
	if len(header) < len(basicAuthPrefix) || !strings.EqualFold(header[:len(basicAuthPrefix)], basicAuthPrefix) {
		return false
	}

	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(basicAuthPrefix):]))
	if err != nil {
		return false
	}
	name, secret, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}

	nameDigest := sha256.Sum256([]byte(name))
	secretDigest := sha256.Sum256([]byte(secret))
	matched := 0
	for _, credential := range p.cfg.Credentials {
		credentialName := sha256.Sum256([]byte(credential.Name))
		credentialSecret := sha256.Sum256([]byte(credential.Secret))
		nameMatches := subtle.ConstantTimeCompare(nameDigest[:], credentialName[:])
		secretMatches := subtle.ConstantTimeCompare(secretDigest[:], credentialSecret[:])
		matched |= nameMatches & secretMatches
	}
	return matched == 1
}

func (p *Proxy) tunnel(w http.ResponseWriter, r *http.Request) {
	target, err := p.reach(r.Context(), r.Host)
	if err != nil {
		// Still on the normal HTTP path: report the failure without opening a tunnel.
		miso.Errorf("proxy cannot reach %s: %v", r.Host, err)
		writeStatus(w, http.StatusBadGateway)
		return
	}
	defer target.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "proxy does not support hijacking", http.StatusInternalServerError)
		return
	}
	client, clientBuffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	if _, err := clientBuffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := clientBuffer.Flush(); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(target, clientBuffer.Reader)
		// The client finished sending: signal EOF to the target but keep reading the
		// reverse direction so a half-closed request can still receive its response.
		closeWrite(target)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
		// The target ended, so no bytes can flow back to the client any more. Close
		// the client fully: this unblocks the surviving client->target copy instead of
		// leaving it parked on a read that will never finish. A client that only
		// half-closed its write side still took the other branch, so its request
		// reaches the target and the reply above was already delivered in full.
		_ = client.Close()
	}()
	wg.Wait()
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

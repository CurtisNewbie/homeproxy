package proxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
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

type Proxy struct {
	cfg       config.Config
	transport *http.Transport
}

func New(cfg config.Config) *Proxy {
	p := &Proxy{cfg: cfg}
	p.transport = &http.Transport{
		DialContext:        p.dialContext,
		DisableCompression: true, // a proxy forwards the client's Accept-Encoding instead of negotiating its own
	}
	return p
}

// dialContext is the single egress seam: every outbound HTTP request reaches its
// target through it, so later tickets can route through an upstream or apply host
// policy in one place.
func (p *Proxy) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: p.cfg.DialTimeout}
	return dialer.DialContext(ctx, network, address)
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
		writeStatus(w, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

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
	target, err := p.dialContext(r.Context(), "tcp", r.Host)
	if err != nil {
		// Still on the normal HTTP path: report the failure without opening a tunnel.
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

package proxy

import (
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
	cfg config.Config
}

func New(cfg config.Config) *Proxy {
	return &Proxy{cfg: cfg}
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

	if r.Method != http.MethodConnect {
		// Ticket 03 forwards absolute-form requests. Until then the proxy holds no
		// forwarding path and answers explicitly rather than pretending to succeed.
		writeStatus(w, http.StatusNotImplemented)
		return
	}

	p.tunnel(w, r)
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
	target, err := net.DialTimeout("tcp", r.Host, p.cfg.DialTimeout)
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

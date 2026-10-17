package proxy

import (
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/curtisnewbie/homeproxy/internal/config"
	"github.com/curtisnewbie/miso/miso"
)

const (
	proxyAuthChallenge     = `Basic realm="homeproxy"`
	proxyReadHeaderTimeout = 10 * time.Second
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
	w.Header().Set("Proxy-Authenticate", proxyAuthChallenge)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusProxyAuthRequired)
}

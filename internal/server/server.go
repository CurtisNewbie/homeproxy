package server

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/curtisnewbie/homeproxy/internal/config"
	"github.com/curtisnewbie/homeproxy/internal/proxy"
	"github.com/curtisnewbie/miso/miso"
)

type service struct {
	cfg         config.Config
	proxyServer *http.Server
}

func BootstrapServer() {
	s := &service{}
	miso.PreServerBootstrap(s.start)
	miso.OnAppReady(s.reportReady)
	miso.BootstrapServer(os.Args)
}

func (s *service) start(rail miso.Rail) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	s.cfg = cfg

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.ProxyPort))
	if err != nil {
		return fmt.Errorf("listen on proxy port %d: %w", cfg.ProxyPort, err)
	}

	s.proxyServer = proxy.Serve(ln, cfg)
	miso.AddShutdownHook(func() { _ = s.proxyServer.Close() })
	return nil
}

func (s *service) reportReady(rail miso.Rail) error {
	rail.Infof("homeproxy listening: proxy port %d, management port %d", s.cfg.ProxyPort, s.cfg.ManagementPort)
	return nil
}

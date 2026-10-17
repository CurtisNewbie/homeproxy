package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"testing"

	"github.com/curtisnewbie/homeproxy/internal/config"
)

func TestProxyAnswersAuthChallenge(t *testing.T) {
	addr := startTestProxy(t)

	tests := []struct {
		name   string
		raw    string
		method string
	}{
		{
			name:   "absolute-form GET",
			raw:    "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n",
			method: http.MethodGet,
		},
		{
			name:   "CONNECT",
			raw:    "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
			method: http.MethodConnect,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", addr)
			if err != nil {
				t.Fatalf("dial proxy: %v", err)
			}
			defer conn.Close()

			if _, err := fmt.Fprint(conn, tt.raw); err != nil {
				t.Fatalf("write request: %v", err)
			}

			resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: tt.method})
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusProxyAuthRequired {
				t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
			}
			if got := resp.Header.Get("Proxy-Authenticate"); got != proxyAuthChallenge {
				t.Errorf("Proxy-Authenticate = %q, want %q", got, proxyAuthChallenge)
			}
			if resp.ContentLength != 0 {
				t.Errorf("Content-Length = %d, want 0", resp.ContentLength)
			}
		})
	}
}

func startTestProxy(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := Serve(ln, config.Config{ProxyPort: ln.Addr().(*net.TCPAddr).Port})
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String()
}

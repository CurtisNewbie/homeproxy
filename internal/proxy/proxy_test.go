package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/curtisnewbie/homeproxy/internal/config"
)

const (
	testCredentialName   = "phone"
	testCredentialSecret = "s3cret"
)

func testProxyConfig() config.Config {
	return config.Config{
		Credentials: []config.Credential{{Name: testCredentialName, Secret: testCredentialSecret}},
		DialTimeout: 2 * time.Second,
	}
}

func basicAuth(name, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+secret))
}

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

func TestProxyConnectWithoutCredentialGetsChallengeAndDialsNothing(t *testing.T) {
	targetAddr, accepted := startCountingTarget(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())

	conn := dialProxy(t, addr)
	writeConnect(t, conn, targetAddr, "")
	_, status, headers := readResponseHead(t, bufio.NewReader(conn))

	if status != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want %d", status, http.StatusProxyAuthRequired)
	}
	if got := headers.Get("Proxy-Authenticate"); got != proxyAuthChallenge {
		t.Errorf("Proxy-Authenticate = %q, want %q", got, proxyAuthChallenge)
	}
	if got := headers.Get("Content-Length"); got != "0" {
		t.Errorf("Content-Length = %q, want 0", got)
	}

	time.Sleep(100 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Errorf("target accepted %d connection(s), want 0", n)
	}
}

func TestProxyRejectsUnknownNameAndWrongSecretIdentically(t *testing.T) {
	targetAddr, accepted := startCountingTarget(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())

	authorizations := []struct {
		name string
		auth string
	}{
		{name: "unknown name", auth: basicAuth("stranger", testCredentialSecret)},
		{name: "wrong secret", auth: basicAuth(testCredentialName, "wrong-secret")},
	}

	type rejection struct {
		status int
		header http.Header
	}
	got := make([]rejection, 0, len(authorizations))
	for _, tc := range authorizations {
		conn := dialProxy(t, addr)
		writeConnect(t, conn, targetAddr, tc.auth)
		_, status, headers := readResponseHead(t, bufio.NewReader(conn))
		_ = conn.Close()
		got = append(got, rejection{status: status, header: headers})
	}

	for i, tc := range authorizations {
		if got[i].status != http.StatusProxyAuthRequired {
			t.Errorf("%s: status = %d, want %d", tc.name, got[i].status, http.StatusProxyAuthRequired)
		}
		if v := got[i].header.Get("Proxy-Authenticate"); v != proxyAuthChallenge {
			t.Errorf("%s: Proxy-Authenticate = %q, want %q", tc.name, v, proxyAuthChallenge)
		}
		if v := got[i].header.Get("Content-Length"); v != "0" {
			t.Errorf("%s: Content-Length = %q, want 0", tc.name, v)
		}
	}

	first, second := got[0], got[1]
	if first.status != second.status {
		t.Errorf("status differs: %d vs %d", first.status, second.status)
	}
	for _, name := range []string{"Proxy-Authenticate", "Content-Length", "WWW-Authenticate"} {
		if first.header.Get(name) != second.header.Get(name) {
			t.Errorf("%s differs: %q vs %q", name, first.header.Get(name), second.header.Get(name))
		}
	}

	time.Sleep(100 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Errorf("target accepted %d connection(s), want 0", n)
	}
}

func TestProxyAcceptsValidCredentialOnConnect(t *testing.T) {
	targetAddr, _ := startCountingTarget(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	writeConnect(t, conn, targetAddr, "")
	if _, status, _ := readResponseHead(t, br); status != http.StatusProxyAuthRequired {
		t.Fatalf("unauthenticated CONNECT status = %d, want %d", status, http.StatusProxyAuthRequired)
	}

	writeConnect(t, conn, targetAddr, basicAuth(testCredentialName, testCredentialSecret))
	if _, status, headers := readResponseHead(t, br); status != http.StatusOK {
		t.Fatalf("authenticated CONNECT status = %d, want %d (headers: %v)", status, http.StatusOK, headers)
	}
}

func TestProxyAcceptsPreemptiveCredentialOnConnect(t *testing.T) {
	targetAddr, _ := startCountingTarget(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeConnect(t, conn, targetAddr, basicAuth(testCredentialName, testCredentialSecret))
	if _, status, headers := readResponseHead(t, bufio.NewReader(conn)); status != http.StatusOK {
		t.Fatalf("preemptive CONNECT status = %d, want %d (headers: %v)", status, http.StatusOK, headers)
	}
}

func TestProxyTunnelsTLSTrafficToTarget(t *testing.T) {
	const responseBody = "hello through the tunnel"
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", r.Method, responseBody)
	}))
	defer target.Close()

	targetAddr := strings.TrimPrefix(target.URL, "https://")
	addr := startTestProxyWithConfig(t, testProxyConfig())

	tunnel := openTunnel(t, addr, targetAddr, basicAuth(testCredentialName, testCredentialSecret))

	tlsConn := tls.Client(tunnel, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake through tunnel: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "https://"+targetAddr+"/", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if err := req.Write(tlsConn); err != nil {
		t.Fatalf("write request through tunnel: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		t.Fatalf("read response through tunnel: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	want := http.MethodGet + " " + responseBody
	if string(body) != want {
		t.Errorf("response body = %q, want %q", body, want)
	}
}

func TestProxyTunnelPreservesHalfClose(t *testing.T) {
	const payload = "request body that ends with a half-close"
	reply := strings.Repeat("response-chunk-", 4096)

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })

	targetResult := make(chan error, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			targetResult <- err
			return
		}
		defer conn.Close()

		got, err := io.ReadAll(conn)
		if err != nil {
			targetResult <- err
			return
		}
		if string(got) != payload {
			targetResult <- fmt.Errorf("target read %q, want %q", got, payload)
			return
		}
		_, err = io.WriteString(conn, reply)
		targetResult <- err
	}()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := openTunnel(t, addr, targetLn.Addr().String(), basicAuth(testCredentialName, testCredentialSecret))

	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write request: %v", err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("half-close client write side: %v", err)
	}

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read reply after half-close: %v", err)
	}
	if string(got) != reply {
		t.Errorf("reply length = %d, want %d", len(got), len(reply))
	}

	if err := <-targetResult; err != nil {
		t.Errorf("target side: %v", err)
	}
}

func TestProxyTunnelClosesWhenTargetEndsAndListenerKeepsServing(t *testing.T) {
	const farewell = "target-finished"

	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, farewell)
		_ = conn.Close()
	}()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := openTunnel(t, addr, targetLn.Addr().String(), basicAuth(testCredentialName, testCredentialSecret))

	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after target ended: %v", err)
	}
	if string(got) != farewell {
		t.Errorf("tunnel delivered %q, want %q", got, farewell)
	}

	assertProxyStillServing(t, addr)
}

func TestProxyClosesIdleClientWhenTargetEnds(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		_ = conn.Close()
	}()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := openTunnel(t, addr, targetLn.Addr().String(), basicAuth(testCredentialName, testCredentialSecret))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	var buf [1]byte
	n, err := conn.Read(buf[:])
	if n != 0 {
		t.Fatalf("read %d byte(s) from closed tunnel, want 0", n)
	}
	if err == nil {
		t.Fatal("idle tunnel read succeeded, want EOF")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("idle tunnel stayed open until the deadline: %v", err)
	}
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read error = %v, want EOF", err)
	}

	assertProxyStillServing(t, addr)
}

func TestProxyTunnelClosesTargetWhenClientEnds(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = targetLn.Close() })

	targetEnded := make(chan error, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			targetEnded <- err
			return
		}
		defer conn.Close()
		_, err = io.ReadAll(conn)
		targetEnded <- err
	}()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := openTunnel(t, addr, targetLn.Addr().String(), basicAuth(testCredentialName, testCredentialSecret))
	_ = conn.Close()

	select {
	case err := <-targetEnded:
		if err != nil {
			t.Errorf("target read: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("target connection was not closed after the client ended")
	}

	assertProxyStillServing(t, addr)
}

func TestProxyAnswersBadGatewayWhenTargetDialFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dead target: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeConnect(t, conn, deadAddr, basicAuth(testCredentialName, testCredentialSecret))
	_, status, headers := readResponseHead(t, bufio.NewReader(conn))

	if status != http.StatusBadGateway {
		t.Errorf("status = %d, want %d (headers: %v)", status, http.StatusBadGateway, headers)
	}

	assertProxyStillServing(t, addr)
}

func assertProxyStillServing(t *testing.T, addr string) {
	t.Helper()

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeConnect(t, conn, "127.0.0.1:1", "")

	_, status, _ := readResponseHead(t, bufio.NewReader(conn))
	if status != http.StatusProxyAuthRequired {
		t.Errorf("proxy after tunnel status = %d, want %d", status, http.StatusProxyAuthRequired)
	}
}

func startTestProxy(t *testing.T) string {
	t.Helper()
	return startTestProxyWithConfig(t, config.Config{})
}

func startTestProxyWithConfig(t *testing.T, cfg config.Config) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cfg.ProxyPort = ln.Addr().(*net.TCPAddr).Port
	srv := Serve(ln, cfg)
	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String()
}

func startCountingTarget(t *testing.T) (addr string, accepted *atomic.Int32) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	var count atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			count.Add(1)
			_ = conn.Close()
		}
	}()

	return ln.Addr().String(), &count
}

func dialProxy(t *testing.T, addr string) *net.TCPConn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn.(*net.TCPConn)
}

func openTunnel(t *testing.T, proxyAddr, targetAddr, auth string) *bufferedConn {
	t.Helper()

	conn := dialProxy(t, proxyAddr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeConnect(t, conn, targetAddr, auth)

	br := bufio.NewReader(conn)
	statusLine, status, headers := readResponseHead(t, br)
	if status != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want %d (headers: %v)", status, http.StatusOK, headers)
	}
	if want := "HTTP/1.1 200 Connection Established"; statusLine != want {
		t.Fatalf("CONNECT status line = %q, want %q", statusLine, want)
	}
	// Keep the reader: bytes written by the target can already sit in this buffer.
	return &bufferedConn{Conn: conn, r: br}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *bufferedConn) CloseWrite() error {
	if cw, ok := c.Conn.(closeWriter); ok {
		return cw.CloseWrite()
	}
	return c.Conn.Close()
}

func writeConnect(t *testing.T, conn net.Conn, target, auth string) {
	t.Helper()

	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if auth != "" {
		fmt.Fprintf(&request, "Proxy-Authorization: %s\r\n", auth)
	}
	request.WriteString("\r\n")

	if _, err := io.WriteString(conn, request.String()); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
}

func readResponseHead(t *testing.T, br *bufio.Reader) (string, int, http.Header) {
	t.Helper()

	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	statusLine = strings.TrimRight(statusLine, "\r\n")
	fields := strings.Fields(statusLine)
	if len(fields) < 2 {
		t.Fatalf("malformed status line %q", statusLine)
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		t.Fatalf("parse status from %q: %v", statusLine, err)
	}

	headers := http.Header{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read header: %v", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			return statusLine, status, headers
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("malformed header %q", line)
		}
		headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
}

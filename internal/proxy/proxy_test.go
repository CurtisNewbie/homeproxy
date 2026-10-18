package proxy

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/curtisnewbie/homeproxy/internal/config"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

const (
	testCredentialName   = "phone"
	testCredentialSecret = "s3cret"
)

func testProxyConfig() config.Config {
	return config.Config{
		Credentials: []config.Credential{{Name: testCredentialName, Secret: testCredentialSecret}},
		DialTimeout: 2 * time.Second,
		// Fixture servers listen on loopback, which the private-network guard
		// refuses unless the host is declared as ours. Tests that exercise the
		// guard clear this on purpose.
		Bypass: []string{"127.0.0.1"},
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
	dialBefore := histogramCount(t, "homeproxy_dial_duration")

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

	if n := accepted.Load(); n != 0 {
		t.Errorf("target accepted %d connection(s), want 0", n)
	}
	assertNoDial(t, dialBefore)
}

func TestProxyRejectsUnknownNameAndWrongSecretIdentically(t *testing.T) {
	targetAddr, accepted := startCountingTarget(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())
	dialBefore := histogramCount(t, "homeproxy_dial_duration")

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

	if n := accepted.Load(); n != 0 {
		t.Errorf("target accepted %d connection(s), want 0", n)
	}
	assertNoDial(t, dialBefore)
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

func TestProxyForwardsAbsoluteFormGET(t *testing.T) {
	requests := make(chan targetCapture, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(t, r)
		w.Header().Set("X-Target", "target-header")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "target response body")
	}))
	defer target.Close()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeAbsoluteFormRequest(t, conn, http.MethodGet, target.URL+"/resource?q=1",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if got := resp.Header.Get("X-Target"); got != "target-header" {
		t.Errorf("X-Target = %q, want %q", got, "target-header")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "target response body" {
		t.Errorf("response body = %q, want %q", body, "target response body")
	}

	got := waitForCapture(t, requests)
	if got.method != http.MethodGet {
		t.Errorf("target method = %q, want %q", got.method, http.MethodGet)
	}
	if got.uri != "/resource?q=1" {
		t.Errorf("target request URI = %q, want %q", got.uri, "/resource?q=1")
	}
}

func TestProxyForwardsAbsoluteFormPOSTBody(t *testing.T) {
	const requestBody = `{"message":"payload that must survive the proxy"}`
	requests := make(chan targetCapture, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(t, r)
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "stored")
	}))
	defer target.Close()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeAbsoluteFormRequest(t, conn, http.MethodPost, target.URL+"/items",
		basicAuth(testCredentialName, testCredentialSecret),
		map[string]string{"Content-Type": "application/json"}, requestBody)

	resp := readProxyResponse(t, conn, http.MethodPost)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "stored" {
		t.Errorf("response body = %q, want %q", body, "stored")
	}

	got := waitForCapture(t, requests)
	if got.method != http.MethodPost {
		t.Errorf("target method = %q, want %q", got.method, http.MethodPost)
	}
	if got.uri != "/items" {
		t.Errorf("target request URI = %q, want %q", got.uri, "/items")
	}
	if got.body != requestBody {
		t.Errorf("target request body = %q, want %q", got.body, requestBody)
	}
}

func TestProxyRejectsNonAbsoluteRequestPath(t *testing.T) {
	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	raw := "GET /local/path HTTP/1.1\r\nHost: example.com\r\n" +
		"Proxy-Authorization: " + basicAuth(testCredentialName, testCredentialSecret) + "\r\n\r\n"
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write origin-form request: %v", err)
	}

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("response body = %q, want empty", body)
	}
}

func TestProxyDoesNotForwardProxyCredentials(t *testing.T) {
	requests := make(chan targetCapture, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(t, r)
		w.Header().Set("X-Target", "ok")
		_, _ = io.WriteString(w, "done")
	}))
	defer target.Close()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeAbsoluteFormRequest(t, conn, http.MethodGet, target.URL+"/private",
		basicAuth(testCredentialName, testCredentialSecret),
		map[string]string{"Proxy-Connection": "keep-alive", "X-Client-Header": "kept"}, "")

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "done" {
		t.Errorf("response body = %q, want %q", body, "done")
	}

	got := waitForCapture(t, requests)
	for _, name := range []string{"Proxy-Authorization", "Proxy-Connection"} {
		if value := got.header.Get(name); value != "" {
			t.Errorf("%s reached the target as %q, want it consumed at the proxy", name, value)
		}
	}
	if value := got.header.Get("X-Client-Header"); value != "kept" {
		t.Errorf("X-Client-Header = %q, want %q", value, "kept")
	}
}

func TestProxyStripsHopByHopHeaders(t *testing.T) {
	requests := make(chan targetCapture, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(t, r)
		w.Header().Set("Connection", "X-Target-Hop")
		w.Header().Set("X-Target-Hop", "secret")
		w.Header().Set("Keep-Alive", "timeout=5")
		w.Header().Set("X-Response-End-To-End", "kept")
		_, _ = io.WriteString(w, "body")
	}))
	defer target.Close()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeAbsoluteFormRequest(t, conn, http.MethodGet, target.URL+"/headers",
		basicAuth(testCredentialName, testCredentialSecret),
		map[string]string{
			"Connection":       "X-Request-Hop",
			"X-Request-Hop":    "secret",
			"Keep-Alive":       "timeout=5",
			"TE":               "trailers",
			"Upgrade":          "websocket",
			"Proxy-Connection": "keep-alive",
			"X-End-To-End":     "kept",
		}, "")

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "body" {
		t.Errorf("response body = %q, want %q", body, "body")
	}
	for _, name := range []string{"Connection", "X-Target-Hop", "Keep-Alive", "Proxy-Connection"} {
		if value := resp.Header.Get(name); value != "" {
			t.Errorf("response header %s = %q, want it stripped", name, value)
		}
	}
	if value := resp.Header.Get("X-Response-End-To-End"); value != "kept" {
		t.Errorf("X-Response-End-To-End = %q, want %q", value, "kept")
	}

	got := waitForCapture(t, requests)
	for _, name := range []string{"Connection", "X-Request-Hop", "Keep-Alive", "TE", "Upgrade", "Proxy-Connection"} {
		if value := got.header.Get(name); value != "" {
			t.Errorf("%s reached the target as %q, want it stripped", name, value)
		}
	}
	if value := got.header.Get("X-End-To-End"); value != "kept" {
		t.Errorf("X-End-To-End = %q, want %q", value, "kept")
	}
}

func TestProxyStreamsResponseIncrementally(t *testing.T) {
	const firstChunk = "first-chunk-"
	const secondChunk = "second-chunk"

	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseTarget := func() { releaseOnce.Do(func() { close(release) }) }

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, firstChunk)
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, secondChunk)
	}))
	t.Cleanup(func() {
		releaseTarget()
		target.Close()
	})

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	writeAbsoluteFormRequest(t, conn, http.MethodGet, target.URL+"/stream",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response head while the target was still writing: %v", err)
	}
	defer resp.Body.Close()

	got := make([]byte, len(firstChunk))
	if _, err := io.ReadFull(resp.Body, got); err != nil {
		t.Fatalf("read first chunk while the target was still writing: %v", err)
	}
	if string(got) != firstChunk {
		t.Errorf("first chunk = %q, want %q", got, firstChunk)
	}

	releaseTarget()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	rest, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read remainder after the target finished: %v", err)
	}
	if string(rest) != secondChunk {
		t.Errorf("remainder = %q, want %q", rest, secondChunk)
	}
}

func TestProxyChallengesUnauthenticatedForwardBeforeDialing(t *testing.T) {
	targetAddr, accepted := startCountingTarget(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())
	dialBefore := histogramCount(t, "homeproxy_dial_duration")

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodGet, "http://"+targetAddr+"/", "", nil, "")

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusProxyAuthRequired)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got != proxyAuthChallenge {
		t.Errorf("Proxy-Authenticate = %q, want %q", got, proxyAuthChallenge)
	}
	if resp.ContentLength != 0 {
		t.Errorf("Content-Length = %d, want 0", resp.ContentLength)
	}

	if n := accepted.Load(); n != 0 {
		t.Errorf("target accepted %d connection(s), want 0", n)
	}
	assertNoDial(t, dialBefore)
}

func TestProxyAnswersBadGatewayWhenForwardTargetFails(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dead target: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeAbsoluteFormRequest(t, conn, http.MethodGet, "http://"+deadAddr+"/",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	assertProxyStillServing(t, addr)
}

func TestProxyDoesNotNegotiateCompression(t *testing.T) {
	var compressed bytes.Buffer
	gzipWriter := gzip.NewWriter(&compressed)
	_, _ = gzipWriter.Write([]byte("compressible payload that the proxy must not inflate"))
	if err := gzipWriter.Close(); err != nil {
		t.Fatalf("build gzip body: %v", err)
	}
	encoded := compressed.Bytes()

	requests := make(chan targetCapture, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests <- captureRequest(t, r)
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(len(encoded)))
		_, _ = w.Write(encoded)
	}))
	defer target.Close()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	// The client sends no Accept-Encoding, so the proxy must not negotiate one.
	writeAbsoluteFormRequest(t, conn, http.MethodGet, target.URL+"/compressed",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if got := resp.Header.Get("Content-Encoding"); got != "gzip" {
		t.Errorf("Content-Encoding = %q, want %q", got, "gzip")
	}
	if resp.ContentLength != int64(len(encoded)) {
		t.Errorf("Content-Length = %d, want %d", resp.ContentLength, len(encoded))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !bytes.Equal(body, encoded) {
		t.Errorf("body length = %d, want the %d compressed bytes unchanged", len(body), len(encoded))
	}

	got := waitForCapture(t, requests)
	if encoding := got.header.Get("Accept-Encoding"); encoding != "" {
		t.Errorf("target saw Accept-Encoding %q, want the proxy to add none", encoding)
	}
}

func TestProxyAbortsClientOnTruncatedResponse(t *testing.T) {
	const chunk = "hello"

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
		defer conn.Close()

		request, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_ = request.Body.Close()
		// Announce a chunked body, deliver one chunk, then vanish without the
		// terminal zero chunk: the response is truncated mid-stream.
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n"+chunk+"\r\n")
	}()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	writeAbsoluteFormRequest(t, conn, http.MethodGet, "http://"+targetLn.Addr().String()+"/truncated",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err == nil {
		t.Fatalf("truncated response read as complete, body = %q", body)
	}
	if string(body) != chunk {
		t.Errorf("body before truncation = %q, want %q", body, chunk)
	}
}

func TestProxyTunnelHasNoIdleTimeoutThroughUpstream(t *testing.T) {
	const payload = "bytes after the upstream handshake deadline"

	backendAddr := startEchoTarget(t)
	upstream := startFakeUpstream(t)
	upstream.setBackend(backendAddr)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	cfg.DialTimeout = 150 * time.Millisecond
	addr := startTestProxyWithConfig(t, cfg)

	tunnel := openTunnel(t, addr, publicTargetAuthority(t, backendAddr), basicAuth(testCredentialName, testCredentialSecret))
	// The dial timeout covers only dialling and the upstream handshake: a tunnel
	// that stays quiet past it must still carry bytes afterwards.
	time.Sleep(4 * cfg.DialTimeout)

	if _, err := io.WriteString(tunnel, payload); err != nil {
		t.Fatalf("write after idle period: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnel, got); err != nil {
		t.Fatalf("read echo after idle period: %v", err)
	}
	if string(got) != payload {
		t.Errorf("echoed bytes = %q, want %q", got, payload)
	}
}

func TestProxyTunnelPreservesBytesBufferedWithUpstreamConnectReply(t *testing.T) {
	const greeting = "banner-sent-with-the-connect-reply"
	const payload = "ping after the banner"

	targetAddr := startEchoTarget(t)
	upstream := startFakeUpstream(t)
	upstream.setBackend(targetAddr)
	upstream.setGreeting(greeting)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	addr := startTestProxyWithConfig(t, cfg)

	tunnel := openTunnel(t, addr, publicTargetAuthority(t, targetAddr), basicAuth(testCredentialName, testCredentialSecret))

	got := make([]byte, len(greeting))
	if _, err := io.ReadFull(tunnel, got); err != nil {
		t.Fatalf("read greeting sent with the CONNECT reply: %v", err)
	}
	if string(got) != greeting {
		t.Errorf("greeting = %q, want %q", got, greeting)
	}

	if _, err := io.WriteString(tunnel, payload); err != nil {
		t.Fatalf("write after greeting: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnel, echo); err != nil {
		t.Fatalf("read echo after greeting: %v", err)
	}
	if string(echo) != payload {
		t.Errorf("echo = %q, want %q", echo, payload)
	}
}

func TestProxyTunnelPreservesHalfCloseThroughUpstream(t *testing.T) {
	const payload = "request body that ends with a half-close"
	reply := strings.Repeat("upstream-response-chunk-", 4096)

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

	upstream := startFakeUpstream(t)
	upstream.setBackend(targetLn.Addr().String())
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	addr := startTestProxyWithConfig(t, cfg)

	conn := openTunnel(t, addr, publicTargetAuthority(t, targetLn.Addr().String()), basicAuth(testCredentialName, testCredentialSecret))
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

func TestProxyAnswersBadGatewayWhenUpstreamRejectsForwardedRequest(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = io.WriteString(w, "should not be reached")
	}))
	defer target.Close()

	upstream := startFakeUpstream(t)
	upstream.requireAuth.Store(true)
	upstream.expectedAuth.Store(basicAuth("upstream-user", "a-different-secret"))

	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	cfg.UpstreamUsername = testCredentialName
	cfg.UpstreamPassword = testCredentialSecret
	addr := startTestProxyWithConfig(t, cfg)

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodGet, publicTargetURL(t, target.URL)+"/rejected",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status = %d, want %d: an upstream auth failure is not the client's 407", resp.StatusCode, http.StatusBadGateway)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got != "" {
		t.Errorf("Proxy-Authenticate = %q, want the upstream challenge withheld", got)
	}
	if n := targetHits.Load(); n != 0 {
		t.Errorf("target hit %d time(s), want 0", n)
	}

	assertProxyStillServing(t, addr)
}

func TestProxyUnreachableUpstreamYieldsBadGatewayAndKeepsServing(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dead upstream: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	cfg := testProxyConfig()
	cfg.Upstream = deadAddr
	addr := startTestProxyWithConfig(t, cfg)

	// A public, non-routable authority: the guard allows it, so the failure can
	// only come from the dead upstream.
	const target = "203.0.113.7:1"

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeConnect(t, conn, target, basicAuth(testCredentialName, testCredentialSecret))
	if _, status, headers := readResponseHead(t, bufio.NewReader(conn)); status != http.StatusBadGateway {
		t.Errorf("tunnel status with unreachable upstream = %d, want %d (headers: %v)", status, http.StatusBadGateway, headers)
	}
	_ = conn.Close()

	conn = dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodGet, "http://"+target+"/",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")
	if resp := readProxyResponse(t, conn, http.MethodGet); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("forward status with unreachable upstream = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	assertProxyStillServing(t, addr)
}

func TestProxyRefusedUpstreamConnectYieldsBadGatewayThenServesNext(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "recovered")
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	upstream := startFakeUpstream(t)
	upstream.setBackend(targetAddr)
	upstream.refuseConnect.Store(true)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	addr := startTestProxyWithConfig(t, cfg)

	publicTarget := publicTargetAuthority(t, targetAddr)

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeConnect(t, conn, publicTarget, basicAuth(testCredentialName, testCredentialSecret))
	if _, status, headers := readResponseHead(t, bufio.NewReader(conn)); status != http.StatusBadGateway {
		t.Errorf("status after refused upstream CONNECT = %d, want %d (headers: %v)", status, http.StatusBadGateway, headers)
	}
	_ = conn.Close()

	upstream.refuseConnect.Store(false)
	tunnel := openTunnel(t, addr, publicTarget, basicAuth(testCredentialName, testCredentialSecret))
	status, body := getThroughTunnel(t, tunnel, "http://"+publicTarget+"/after")
	if status != http.StatusOK {
		t.Errorf("next tunnel status = %d, want %d", status, http.StatusOK)
	}
	if body != "recovered" {
		t.Errorf("next tunnel body = %q, want %q", body, "recovered")
	}

	seen := upstream.seen()
	if len(seen) != 2 {
		t.Fatalf("upstream observed %d request(s), want 2: %+v", len(seen), seen)
	}
	for i, obs := range seen {
		if obs.method != http.MethodConnect {
			t.Errorf("upstream request %d method = %q, want %q", i, obs.method, http.MethodConnect)
		}
		if obs.authority != publicTarget {
			t.Errorf("upstream request %d authority = %q, want %q", i, obs.authority, publicTarget)
		}
	}

	assertProxyStillServing(t, addr)
}

func TestProxyDialsDirectlyWhenUpstreamEmpty(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "direct: "+r.URL.Path)
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	upstream := startFakeUpstream(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())

	tunnel := openTunnel(t, addr, targetAddr, basicAuth(testCredentialName, testCredentialSecret))
	status, body := getThroughTunnel(t, tunnel, "http://"+targetAddr+"/tunnelled")
	if status != http.StatusOK {
		t.Errorf("tunnel status = %d, want %d", status, http.StatusOK)
	}
	if body != "direct: /tunnelled" {
		t.Errorf("tunnel body = %q, want %q", body, "direct: /tunnelled")
	}

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodGet, target.URL+"/forwarded",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")
	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("forward status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	forwarded, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read forwarded body: %v", err)
	}
	if string(forwarded) != "direct: /forwarded" {
		t.Errorf("forward body = %q, want %q", forwarded, "direct: /forwarded")
	}

	if n := upstream.acceptCount(); n != 0 {
		t.Errorf("upstream accepted %d connection(s), want 0 when homeproxy.upstream is empty", n)
	}
	if seen := upstream.seen(); len(seen) != 0 {
		t.Errorf("upstream observed %+v, want nothing", seen)
	}
}

func TestProxySendsUpstreamCredentials(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{name: "both configured", username: "up-user", password: "up-secret"},
		{name: "username only", username: "up-user"},
		{name: "none configured"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "ok")
			}))
			defer target.Close()
			targetAddr := strings.TrimPrefix(target.URL, "http://")

			upstream := startFakeUpstream(t)
			upstream.setBackend(targetAddr)
			cfg := testProxyConfig()
			cfg.Upstream = upstream.addr()
			cfg.UpstreamUsername = tt.username
			cfg.UpstreamPassword = tt.password
			addr := startTestProxyWithConfig(t, cfg)

			publicTarget := publicTargetAuthority(t, targetAddr)

			tunnel := openTunnel(t, addr, publicTarget, basicAuth(testCredentialName, testCredentialSecret))
			if status, _ := getThroughTunnel(t, tunnel, "http://"+publicTarget+"/tunnelled"); status != http.StatusOK {
				t.Fatalf("tunnel status = %d, want %d", status, http.StatusOK)
			}

			conn := dialProxy(t, addr)
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			writeAbsoluteFormRequest(t, conn, http.MethodGet, publicTargetURL(t, target.URL)+"/forwarded",
				basicAuth(testCredentialName, testCredentialSecret), nil, "")
			if resp := readProxyResponse(t, conn, http.MethodGet); resp.StatusCode != http.StatusOK {
				t.Fatalf("forward status = %d, want %d", resp.StatusCode, http.StatusOK)
			}

			want := ""
			if tt.username != "" || tt.password != "" {
				want = basicAuth(tt.username, tt.password)
			}
			seen := upstream.seen()
			if len(seen) != 2 {
				t.Fatalf("upstream observed %d request(s), want 2: %+v", len(seen), seen)
			}
			if seen[0].method != http.MethodConnect {
				t.Errorf("first upstream request = %q, want %q", seen[0].method, http.MethodConnect)
			}
			if seen[1].method != http.MethodGet {
				t.Errorf("second upstream request = %q, want %q", seen[1].method, http.MethodGet)
			}
			for _, obs := range seen {
				if obs.proxyAuth != want {
					t.Errorf("%s upstream Proxy-Authorization = %q, want %q", obs.method, obs.proxyAuth, want)
				}
			}
		})
	}
}

func TestProxyForwardsAbsoluteFormThroughUpstream(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Target", "target-header")
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "target response body")
	}))
	defer target.Close()
	targetURL := target.URL + "/resource?q=1"
	publicURL := publicTargetURL(t, targetURL)

	upstream := startFakeUpstream(t)
	upstream.setBackend(strings.TrimPrefix(target.URL, "http://"))
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	addr := startTestProxyWithConfig(t, cfg)

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodGet, publicURL,
		basicAuth(testCredentialName, testCredentialSecret), nil, "")

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusCreated)
	}
	if got := resp.Header.Get("X-Target"); got != "target-header" {
		t.Errorf("X-Target = %q, want %q", got, "target-header")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != "target response body" {
		t.Errorf("response body = %q, want %q", body, "target response body")
	}

	seen := upstream.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream observed %d request(s), want 1: %+v", len(seen), seen)
	}
	got := seen[0]
	if got.method != http.MethodGet {
		t.Errorf("upstream method = %q, want %q", got.method, http.MethodGet)
	}
	if got.requestURI != publicURL {
		t.Errorf("upstream request URI = %q, want the absolute form %q", got.requestURI, publicURL)
	}
	if got.authority != publicTargetAuthority(t, strings.TrimPrefix(target.URL, "http://")) {
		t.Errorf("upstream request authority = %q, want %q", got.authority, publicTargetAuthority(t, strings.TrimPrefix(target.URL, "http://")))
	}
}

func TestProxyTunnelsThroughUpstream(t *testing.T) {
	const responseBody = "target response through the upstream tunnel"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, responseBody)
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	upstream := startFakeUpstream(t)
	upstream.setBackend(targetAddr)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	addr := startTestProxyWithConfig(t, cfg)

	publicTarget := publicTargetAuthority(t, targetAddr)
	tunnel := openTunnel(t, addr, publicTarget, basicAuth(testCredentialName, testCredentialSecret))
	status, body := getThroughTunnel(t, tunnel, "http://"+publicTarget+"/tunnelled")
	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	if body != responseBody {
		t.Errorf("response body = %q, want %q", body, responseBody)
	}

	seen := upstream.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream observed %d request(s), want 1: %+v", len(seen), seen)
	}
	got := seen[0]
	if got.method != http.MethodConnect {
		t.Errorf("upstream method = %q, want %q", got.method, http.MethodConnect)
	}
	if got.authority != publicTarget {
		t.Errorf("upstream CONNECT authority = %q, want %q", got.authority, publicTarget)
	}
	if got.requestURI != publicTarget {
		t.Errorf("upstream CONNECT request URI = %q, want %q", got.requestURI, publicTarget)
	}
}

func TestProxyRoutesPublicHostThroughUpstream(t *testing.T) {
	const payload = "public target reached through the upstream"

	backendAddr := startEchoTarget(t)
	upstream := startFakeUpstream(t)
	upstream.setBackend(backendAddr)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	addr := startTestProxyWithConfig(t, cfg)

	publicTarget := publicTargetAuthority(t, backendAddr)
	tunnel := openTunnel(t, addr, publicTarget, basicAuth(testCredentialName, testCredentialSecret))
	if _, err := io.WriteString(tunnel, payload); err != nil {
		t.Fatalf("write through the tunnel: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnel, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(echo) != payload {
		t.Errorf("echo = %q, want %q", echo, payload)
	}

	seen := upstream.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream observed %d request(s), want 1: %+v", len(seen), seen)
	}
	if seen[0].method != http.MethodConnect || seen[0].authority != publicTarget {
		t.Errorf("upstream observed %s %s, want CONNECT %s", seen[0].method, seen[0].authority, publicTarget)
	}
}

func TestProxyDialsPublicHostDirectlyWhenUpstreamEmpty(t *testing.T) {
	cfg := testProxyConfig()
	cfg.DialTimeout = 300 * time.Millisecond
	addr := startTestProxyWithConfig(t, cfg)

	const publicTarget = "203.0.113.7:443"
	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeConnect(t, conn, publicTarget, basicAuth(testCredentialName, testCredentialSecret))
	_, status, headers := readResponseHead(t, bufio.NewReader(conn))

	// A public target is not refused: the proxy tries to dial it itself, and the
	// non-routable test address makes that dial fail.
	if status != http.StatusBadGateway {
		t.Errorf("status = %d, want %d for a public target with no upstream (headers: %v)", status, http.StatusBadGateway, headers)
	}

	assertProxyStillServing(t, addr)
}

func TestProxyUsesUpstreamWhenResolutionFails(t *testing.T) {
	upstream := startFakeUpstream(t)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	cfg.Bypass = nil
	addr := startTestProxyWithConfig(t, cfg)

	// .invalid is reserved and never resolves.
	const unresolvable = "does-not-exist.invalid:443"

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeConnect(t, conn, unresolvable, basicAuth(testCredentialName, testCredentialSecret))
	if _, status, headers := readResponseHead(t, bufio.NewReader(conn)); status != http.StatusBadGateway {
		t.Errorf("CONNECT status = %d, want %d (headers: %v)", status, http.StatusBadGateway, headers)
	}
	_ = conn.Close()

	conn = dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodGet, "http://"+unresolvable+"/",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")
	if resp := readProxyResponse(t, conn, http.MethodGet); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("forward status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	seen := upstream.seen()
	if len(seen) != 2 {
		t.Fatalf("upstream observed %d request(s), want 2: %+v", len(seen), seen)
	}
	if seen[0].method != http.MethodConnect || seen[0].authority != unresolvable {
		t.Errorf("upstream observed %s %s, want CONNECT %s", seen[0].method, seen[0].authority, unresolvable)
	}
	if seen[1].method != http.MethodGet {
		t.Errorf("upstream method = %q, want %q", seen[1].method, http.MethodGet)
	}
}

func TestProxyAnswersBadGatewayWhenResolutionFailsWithoutUpstream(t *testing.T) {
	cfg := testProxyConfig()
	cfg.Bypass = nil
	addr := startTestProxyWithConfig(t, cfg)

	const unresolvable = "does-not-exist.invalid:443"

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeConnect(t, conn, unresolvable, basicAuth(testCredentialName, testCredentialSecret))
	if _, status, headers := readResponseHead(t, bufio.NewReader(conn)); status != http.StatusBadGateway {
		t.Errorf("CONNECT status = %d, want %d before hijacking (headers: %v)", status, http.StatusBadGateway, headers)
	}
	_ = conn.Close()

	conn = dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodGet, "http://"+unresolvable+"/",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")
	if resp := readProxyResponse(t, conn, http.MethodGet); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("forward status = %d, want %d", resp.StatusCode, http.StatusBadGateway)
	}

	assertProxyStillServing(t, addr)
}

func TestProxyForbidsPrivateTargetBeforeUpstreamSeesIt(t *testing.T) {
	upstream := startFakeUpstream(t)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	cfg.Bypass = nil
	addr := startTestProxyWithConfig(t, cfg)

	const privateTarget = "10.1.2.3:443"

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeConnect(t, conn, privateTarget, basicAuth(testCredentialName, testCredentialSecret))
	if _, status, headers := readResponseHead(t, bufio.NewReader(conn)); status != http.StatusForbidden {
		t.Errorf("CONNECT status = %d, want %d (headers: %v)", status, http.StatusForbidden, headers)
	}
	_ = conn.Close()

	conn = dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodGet, "http://"+privateTarget+"/",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")
	if resp := readProxyResponse(t, conn, http.MethodGet); resp.StatusCode != http.StatusForbidden {
		t.Errorf("forward status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}

	if n := upstream.acceptCount(); n != 0 {
		t.Errorf("upstream accepted %d connection(s), want 0", n)
	}
	if seen := upstream.seen(); len(seen) != 0 {
		t.Errorf("upstream observed %+v, want nothing", seen)
	}

	assertProxyStillServing(t, addr)
}

func nonPublicTargets(t *testing.T, loopbackAddr string) []string {
	t.Helper()

	_, port, err := net.SplitHostPort(loopbackAddr)
	if err != nil {
		t.Fatalf("split loopback address %q: %v", loopbackAddr, err)
	}
	// One literal per denied range: loopback, RFC1918, link-local (which covers
	// the metadata address), CGNAT, multicast, IPv6 loopback, IPv4 0/8,
	// benchmarking and reserved (which includes broadcast).
	return []string{
		loopbackAddr,
		net.JoinHostPort("::1", port),
		"10.1.2.3:443",
		"172.16.5.4:443",
		"192.168.1.10:443",
		"169.254.169.254:80",
		"100.64.0.1:443",
		"224.0.0.1:443",
		"0.0.0.0:443",
		"198.18.0.1:443",
		"240.0.0.1:443",
	}
}

func TestProxyForbidsConnectToNonPublicAddresses(t *testing.T) {
	loopbackAddr, accepted := startCountingTarget(t)
	targets := nonPublicTargets(t, loopbackAddr)

	cfg := testProxyConfig()
	cfg.Bypass = nil // nothing is exempt: the guard decides on every target
	addr := startTestProxyWithConfig(t, cfg)
	dialBefore := histogramCount(t, "homeproxy_dial_duration")

	for _, target := range targets {
		conn := dialProxy(t, addr)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		writeConnect(t, conn, target, basicAuth(testCredentialName, testCredentialSecret))
		_, status, headers := readResponseHead(t, bufio.NewReader(conn))
		_ = conn.Close()

		if status != http.StatusForbidden {
			t.Errorf("CONNECT %s status = %d, want %d (headers: %v)", target, status, http.StatusForbidden, headers)
		}
	}

	if n := accepted.Load(); n != 0 {
		t.Errorf("loopback target accepted %d connection(s), want 0", n)
	}
	assertNoDial(t, dialBefore)

	assertProxyStillServing(t, addr)
}

func TestProxyForbidsForwardToNonPublicAddresses(t *testing.T) {
	loopbackAddr, accepted := startCountingTarget(t)
	targets := nonPublicTargets(t, loopbackAddr)

	cfg := testProxyConfig()
	cfg.Bypass = nil
	addr := startTestProxyWithConfig(t, cfg)
	dialBefore := histogramCount(t, "homeproxy_dial_duration")

	for _, target := range targets {
		conn := dialProxy(t, addr)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		writeAbsoluteFormRequest(t, conn, http.MethodGet, "http://"+target+"/",
			basicAuth(testCredentialName, testCredentialSecret), nil, "")

		resp := readProxyResponse(t, conn, http.MethodGet)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET http://%s/ status = %d, want %d", target, resp.StatusCode, http.StatusForbidden)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read response body for %s: %v", target, err)
		}
		if len(body) != 0 {
			t.Errorf("GET http://%s/ body = %q, want empty", target, body)
		}
		_ = conn.Close()
	}

	if n := accepted.Load(); n != 0 {
		t.Errorf("loopback target accepted %d connection(s), want 0", n)
	}
	assertNoDial(t, dialBefore)

	assertProxyStillServing(t, addr)
}

func TestProxyBypassExactHostTunnelsDirectDespiteUpstream(t *testing.T) {
	const responseBody = "bypass target reached directly"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, responseBody)
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")
	targetHost, _, err := net.SplitHostPort(targetAddr)
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}

	upstream := startFakeUpstream(t)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	// The target is loopback: a bypass host is dialled and allowed even when it
	// resolves to a private address and an upstream is configured.
	cfg.Bypass = []string{targetHost}
	addr := startTestProxyWithConfig(t, cfg)

	tunnel := openTunnel(t, addr, targetAddr, basicAuth(testCredentialName, testCredentialSecret))
	status, body := getThroughTunnel(t, tunnel, "http://"+targetAddr+"/bypassed")
	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	if body != responseBody {
		t.Errorf("body = %q, want %q", body, responseBody)
	}

	if seen := upstream.seen(); len(seen) != 0 {
		t.Errorf("upstream observed %+v, want the bypass host dialled directly", seen)
	}
}

func TestProxyBypassExactHostForwardsDirectDespiteUpstream(t *testing.T) {
	const responseBody = "forwarded straight to the bypass target"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, responseBody)
	}))
	defer target.Close()
	targetHost, _, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}

	upstream := startFakeUpstream(t)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	cfg.Bypass = []string{targetHost}
	addr := startTestProxyWithConfig(t, cfg)

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodGet, target.URL+"/bypassed",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")

	resp := readProxyResponse(t, conn, http.MethodGet)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != responseBody {
		t.Errorf("body = %q, want %q", body, responseBody)
	}

	if seen := upstream.seen(); len(seen) != 0 {
		t.Errorf("upstream observed %+v, want the bypass host dialled directly", seen)
	}
}

func TestProxyBypassWildcardMatchesSubdomainsNotBareSuffix(t *testing.T) {
	upstream := startFakeUpstream(t)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	cfg.Bypass = []string{"*.localhost"}
	addr := startTestProxyWithConfig(t, cfg)

	connect := func(target string) int {
		t.Helper()
		conn := dialProxy(t, addr)
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		writeConnect(t, conn, target, basicAuth(testCredentialName, testCredentialSecret))
		_, status, _ := readResponseHead(t, bufio.NewReader(conn))
		_ = conn.Close()
		return status
	}

	// A subdomain matches the wildcard: the proxy dials it itself, so the
	// unresolvable host never reaches the upstream.
	if status := connect("sub.localhost:1"); status != http.StatusBadGateway {
		t.Errorf("subdomain status = %d, want %d from the direct dial", status, http.StatusBadGateway)
	}
	if seen := upstream.seen(); len(seen) != 0 {
		t.Errorf("upstream observed %+v after a matching subdomain, want nothing", seen)
	}

	// The bare suffix is not a subdomain and must be listed separately: it keeps
	// using the upstream. A public, non-routable authority stands in for such a
	// host, so the guard lets it through to the upstream instead of refusing it.
	const bareTarget = "203.0.113.7:1"
	if status := connect(bareTarget); status != http.StatusBadGateway {
		t.Errorf("bare suffix status = %d, want %d", status, http.StatusBadGateway)
	}
	seen := upstream.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream observed %d request(s) after the bare suffix, want 1: %+v", len(seen), seen)
	}
	if seen[0].authority != bareTarget {
		t.Errorf("upstream CONNECT authority = %q, want %q", seen[0].authority, bareTarget)
	}
}

func TestProxyBypassMatchIgnoresCaseAndPort(t *testing.T) {
	const responseBody = "matched regardless of case and port"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, responseBody)
	}))
	defer target.Close()
	_, targetPort, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}
	// localhost reaches the same loopback listener, and the target authority
	// carries a port the entry does not.
	targetAddr := net.JoinHostPort("localhost", targetPort)

	upstream := startFakeUpstream(t)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	cfg.Bypass = []string{"LoCaLhOsT"}
	addr := startTestProxyWithConfig(t, cfg)

	tunnel := openTunnel(t, addr, targetAddr, basicAuth(testCredentialName, testCredentialSecret))
	status, body := getThroughTunnel(t, tunnel, "http://"+targetAddr+"/mixed-case")
	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	if body != responseBody {
		t.Errorf("body = %q, want %q", body, responseBody)
	}

	if seen := upstream.seen(); len(seen) != 0 {
		t.Errorf("upstream observed %+v, want a case-insensitive, port-ignoring match", seen)
	}
}

func TestProxyBypassMatchIgnoresTrailingDot(t *testing.T) {
	const responseBody = "matched with a trailing dot"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, responseBody)
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	upstream := startFakeUpstream(t)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	// The configured name carries a trailing dot; the target authority does not.
	cfg.Bypass = []string{"127.0.0.1."}
	addr := startTestProxyWithConfig(t, cfg)

	tunnel := openTunnel(t, addr, targetAddr, basicAuth(testCredentialName, testCredentialSecret))
	status, body := getThroughTunnel(t, tunnel, "http://"+targetAddr+"/trailing-dot")
	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	if body != responseBody {
		t.Errorf("body = %q, want %q", body, responseBody)
	}

	if seen := upstream.seen(); len(seen) != 0 {
		t.Errorf("upstream observed %+v, want a trailing-dot match", seen)
	}
}

// A bypass host that resolves to a public address still uses the direct egress:
// the bypass list, not the address family, selects it.
func TestProxyBypassPublicHostUsesDirectEgress(t *testing.T) {
	const publicTarget = "203.0.113.7:443"

	upstream := startFakeUpstream(t)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	cfg.Bypass = []string{"203.0.113.7"}
	// TEST-NET-3 cannot be reached. The timeout bounds the direct dial, so the
	// 502 comes from the dial budget rather than the network's failure mode.
	cfg.DialTimeout = 200 * time.Millisecond
	addr := startTestProxyWithConfig(t, cfg)
	dialBefore := histogramCount(t, "homeproxy_dial_duration")

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeConnect(t, conn, publicTarget, basicAuth(testCredentialName, testCredentialSecret))
	if _, status, headers := readResponseHead(t, bufio.NewReader(conn)); status != http.StatusBadGateway {
		t.Errorf("CONNECT status = %d, want %d from the direct dial (headers: %v)", status, http.StatusBadGateway, headers)
	}
	_ = conn.Close()

	conn = dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodGet, "http://"+publicTarget+"/",
		basicAuth(testCredentialName, testCredentialSecret), nil, "")
	if resp := readProxyResponse(t, conn, http.MethodGet); resp.StatusCode != http.StatusBadGateway {
		t.Errorf("forward status = %d, want %d from the direct dial", resp.StatusCode, http.StatusBadGateway)
	}

	if seen := upstream.seen(); len(seen) != 0 {
		t.Errorf("upstream observed %+v, want nothing for a bypass host", seen)
	}
	if n := upstream.acceptCount(); n != 0 {
		t.Errorf("upstream accepted %d connection(s), want 0 for a bypass host", n)
	}
	if got := histogramCount(t, "homeproxy_dial_duration"); got < dialBefore+2 {
		t.Errorf("recorded %d direct dial(s), want 2 (tunnel and forward)", got-dialBefore)
	}
}

func TestProxyBypassNonListedHostUsesUpstream(t *testing.T) {
	const responseBody = "ordinary target through the upstream"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, responseBody)
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	upstream := startFakeUpstream(t)
	upstream.setBackend(targetAddr)
	cfg := testProxyConfig()
	cfg.Upstream = upstream.addr()
	cfg.Bypass = []string{"other.localhost"}
	addr := startTestProxyWithConfig(t, cfg)

	publicTarget := publicTargetAuthority(t, targetAddr)
	tunnel := openTunnel(t, addr, publicTarget, basicAuth(testCredentialName, testCredentialSecret))
	status, body := getThroughTunnel(t, tunnel, "http://"+publicTarget+"/ordinary")
	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	if body != responseBody {
		t.Errorf("body = %q, want %q", body, responseBody)
	}

	seen := upstream.seen()
	if len(seen) != 1 {
		t.Fatalf("upstream observed %d request(s), want 1: %+v", len(seen), seen)
	}
	if seen[0].method != http.MethodConnect {
		t.Errorf("upstream method = %q, want %q", seen[0].method, http.MethodConnect)
	}
	if seen[0].authority != publicTarget {
		t.Errorf("upstream CONNECT authority = %q, want %q", seen[0].authority, publicTarget)
	}
}

type targetCapture struct {
	method string
	uri    string
	header http.Header
	body   string
}

func captureRequest(t *testing.T, r *http.Request) targetCapture {
	t.Helper()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Errorf("target read request body: %v", err)
	}
	return targetCapture{method: r.Method, uri: r.URL.RequestURI(), header: r.Header.Clone(), body: string(body)}
}

func waitForCapture(t *testing.T, requests <-chan targetCapture) targetCapture {
	t.Helper()

	select {
	case got := <-requests:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("target received no request")
		return targetCapture{}
	}
}

func writeAbsoluteFormRequest(t *testing.T, conn net.Conn, method, target, auth string, headers map[string]string, body string) {
	t.Helper()

	targetURL, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target URL %q: %v", target, err)
	}

	var request strings.Builder
	fmt.Fprintf(&request, "%s %s HTTP/1.1\r\n", method, target)
	fmt.Fprintf(&request, "Host: %s\r\n", targetURL.Host)
	if auth != "" {
		fmt.Fprintf(&request, "Proxy-Authorization: %s\r\n", auth)
	}
	for name, value := range headers {
		fmt.Fprintf(&request, "%s: %s\r\n", name, value)
	}
	if body != "" {
		fmt.Fprintf(&request, "Content-Length: %d\r\n", len(body))
	}
	request.WriteString("\r\n")
	request.WriteString(body)

	if _, err := io.WriteString(conn, request.String()); err != nil {
		t.Fatalf("write absolute-form request: %v", err)
	}
}

func readProxyResponse(t *testing.T, conn net.Conn, method string) *http.Response {
	t.Helper()

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: method})
	if err != nil {
		t.Fatalf("read proxy response: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
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

type upstreamObservation struct {
	method     string
	authority  string
	requestURI string
	proxyAuth  string
}

// fakeUpstream is a hand-written HTTP proxy: it records what it was asked to
// reach and then either tunnels to the target or forwards an absolute-form
// request, so tests observe the wire behaviour of chaining instead of mocks.
type fakeUpstream struct {
	server        *httptest.Server
	forwarder     *http.Transport
	backend       atomic.Value
	mu            sync.Mutex
	observations  []upstreamObservation
	accepts       atomic.Int32
	refuseConnect atomic.Bool
	requireAuth   atomic.Bool
	expectedAuth  atomic.Value
	greeting      atomic.Value
}

func startFakeUpstream(t *testing.T) *fakeUpstream {
	t.Helper()

	u := &fakeUpstream{forwarder: &http.Transport{}}
	server := httptest.NewUnstartedServer(http.HandlerFunc(u.handle))
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			u.accepts.Add(1)
		}
	}
	server.Start()
	u.server = server
	t.Cleanup(server.Close)
	return u
}

func (u *fakeUpstream) addr() string {
	return strings.TrimPrefix(u.server.URL, "http://")
}

func (u *fakeUpstream) seen() []upstreamObservation {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamObservation(nil), u.observations...)
}

func (u *fakeUpstream) acceptCount() int32 {
	return u.accepts.Load()
}

func (u *fakeUpstream) setGreeting(greeting string) {
	u.greeting.Store(greeting)
}

// setBackend makes the upstream deliver every tunnelled and forwarded request to
// this local server, modelling the internet behind a proxy: the client addresses
// a public authority and the upstream is the one that reaches it.
func (u *fakeUpstream) setBackend(addr string) {
	u.backend.Store(addr)
}

func (u *fakeUpstream) deliveryTarget(authority string) string {
	if backend, _ := u.backend.Load().(string); backend != "" {
		return backend
	}
	return authority
}

// publicTargetAuthority turns a loopback fixture address into a public,
// non-routable authority (TEST-NET-3) with the same port. A test that must route
// through the upstream addresses it, because a loopback target would be refused
// by the private-network guard, and a bypassed host never uses the upstream.
func publicTargetAuthority(t *testing.T, addr string) string {
	t.Helper()

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split fixture address %q: %v", addr, err)
	}
	return net.JoinHostPort("203.0.113.7", port)
}

func publicTargetURL(t *testing.T, targetURL string) string {
	t.Helper()

	parsed, err := url.Parse(targetURL)
	if err != nil {
		t.Fatalf("parse fixture URL %q: %v", targetURL, err)
	}
	parsed.Host = publicTargetAuthority(t, parsed.Host)
	return parsed.String()
}

func (u *fakeUpstream) handle(w http.ResponseWriter, r *http.Request) {
	authority := r.Host
	if authority == "" {
		authority = r.URL.Host
	}
	u.mu.Lock()
	u.observations = append(u.observations, upstreamObservation{
		method:     r.Method,
		authority:  authority,
		requestURI: r.RequestURI,
		proxyAuth:  r.Header.Get("Proxy-Authorization"),
	})
	u.mu.Unlock()

	if u.requireAuth.Load() {
		want, _ := u.expectedAuth.Load().(string)
		if r.Header.Get("Proxy-Authorization") != want {
			w.Header().Set("Proxy-Authenticate", `Basic realm="fake-upstream"`)
			w.Header().Set("Content-Length", "0")
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
	}

	if r.Method == http.MethodConnect {
		if u.refuseConnect.Load() {
			http.Error(w, "connect refused", http.StatusForbidden)
			return
		}
		u.tunnel(w, r)
		return
	}
	u.forward(w, r)
}

func (u *fakeUpstream) tunnel(w http.ResponseWriter, r *http.Request) {
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "upstream cannot hijack", http.StatusInternalServerError)
		return
	}
	client, clientBuffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	target, err := net.DialTimeout("tcp", u.deliveryTarget(r.Host), 2*time.Second)
	if err != nil {
		_, _ = clientBuffer.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		_ = clientBuffer.Flush()
		return
	}
	defer target.Close()

	greeting, _ := u.greeting.Load().(string)
	if _, err := clientBuffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n" + greeting); err != nil {
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
		closeWrite(target)
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, target)
		_ = client.Close()
	}()
	wg.Wait()
}

func (u *fakeUpstream) forward(w http.ResponseWriter, r *http.Request) {
	outreq := r.Clone(r.Context())
	outreq.RequestURI = ""
	outreq.Header.Del("Proxy-Authorization")
	outreq.Header.Del("Proxy-Connection")
	if backend, _ := u.backend.Load().(string); backend != "" {
		outreq.URL.Host = backend
		outreq.Host = backend
	}

	resp, err := u.forwarder.RoundTrip(outreq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func getThroughTunnel(t *testing.T, conn net.Conn, target string) (int, string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("build tunnel request: %v", err)
	}
	if err := req.Write(conn); err != nil {
		t.Fatalf("write tunnel request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read tunnel response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read tunnel response body: %v", err)
	}
	return resp.StatusCode, string(body)
}

func startEchoTarget(t *testing.T) string {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo target: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()

	return ln.Addr().String()
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

func metricFamily(t *testing.T, name string) *dto.MetricFamily {
	t.Helper()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, family := range families {
		if family.GetName() == name {
			return family
		}
	}
	t.Fatalf("metric %q is not exposed by prometheus.DefaultGatherer", name)
	return nil
}

func singleMetric(t *testing.T, name string) *dto.Metric {
	t.Helper()

	metrics := metricFamily(t, name).GetMetric()
	if len(metrics) != 1 {
		t.Fatalf("metric %q has %d samples, want 1", name, len(metrics))
	}
	return metrics[0]
}

func counterValue(t *testing.T, name string) float64 {
	t.Helper()
	return singleMetric(t, name).GetCounter().GetValue()
}

func gaugeValue(t *testing.T, name string) float64 {
	t.Helper()
	return singleMetric(t, name).GetGauge().GetValue()
}

func histogramCount(t *testing.T, name string) uint64 {
	t.Helper()
	return singleMetric(t, name).GetHistogram().GetSampleCount()
}

func waitForCounter(t *testing.T, name string, cond func(float64) bool) float64 {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		got := counterValue(t, name)
		if cond(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s = %v, condition not met within 5s", name, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitForGauge(t *testing.T, name string, cond func(float64) bool) float64 {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		got := gaugeValue(t, name)
		if cond(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s = %v, condition not met within 5s", name, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitForHistogramCount(t *testing.T, name string, cond func(uint64) bool) uint64 {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)
	for {
		got := histogramCount(t, name)
		if cond(got) {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s sample count = %d, condition not met within 5s", name, got)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// assertNoDial checks that no outbound connection was attempted since before was
// recorded. A dial is observed before its caller continues, so once the proxy has
// answered, the count is settled and no waiting is needed.
func assertNoDial(t *testing.T, before uint64) {
	t.Helper()

	if got := histogramCount(t, "homeproxy_dial_duration"); got != before {
		t.Errorf("proxy recorded %d dial(s), want none", got-before)
	}
}

func TestProxyCountsRequestsAndAuthFailures(t *testing.T) {
	targetAddr, accepted := startCountingTarget(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())

	authBefore := counterValue(t, "homeproxy_auth_failures_total")
	requestsBefore := counterValue(t, "homeproxy_requests_total")

	conn := dialProxy(t, addr)
	writeConnect(t, conn, targetAddr, "")
	if _, status, _ := readResponseHead(t, bufio.NewReader(conn)); status != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d", status, http.StatusProxyAuthRequired)
	}

	waitForCounter(t, "homeproxy_auth_failures_total", func(v float64) bool { return v >= authBefore+1 })
	waitForCounter(t, "homeproxy_requests_total", func(v float64) bool { return v >= requestsBefore+1 })

	if n := accepted.Load(); n != 0 {
		t.Errorf("target accepted %d connection(s), want 0", n)
	}
}

func TestProxyTracksActiveTunnels(t *testing.T) {
	targetAddr := startEchoTarget(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())

	baseline := gaugeValue(t, "homeproxy_tunnels_active")

	tunnel := openTunnel(t, addr, targetAddr, basicAuth(testCredentialName, testCredentialSecret))
	waitForGauge(t, "homeproxy_tunnels_active", func(v float64) bool { return v == baseline+1 })

	_ = tunnel.Close()
	waitForGauge(t, "homeproxy_tunnels_active", func(v float64) bool { return v == baseline })
}

func TestProxyCountsTunnelBytes(t *testing.T) {
	const payload = "bytes that cross the tunnel in both directions"

	targetAddr := startEchoTarget(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())

	upBefore := counterValue(t, "homeproxy_bytes_up_total")
	downBefore := counterValue(t, "homeproxy_bytes_down_total")

	tunnel := openTunnel(t, addr, targetAddr, basicAuth(testCredentialName, testCredentialSecret))
	if _, err := io.WriteString(tunnel, payload); err != nil {
		t.Fatalf("write tunnel payload: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnel, echo); err != nil {
		t.Fatalf("read tunnel echo: %v", err)
	}
	if string(echo) != payload {
		t.Fatalf("echo = %q, want %q", echo, payload)
	}
	_ = tunnel.Close()

	size := float64(len(payload))
	waitForCounter(t, "homeproxy_bytes_up_total", func(v float64) bool { return v >= upBefore+size })
	waitForCounter(t, "homeproxy_bytes_down_total", func(v float64) bool { return v >= downBefore+size })

	if got := counterValue(t, "homeproxy_bytes_up_total"); got != upBefore+size {
		t.Errorf("homeproxy_bytes_up_total = %v, want %v", got, upBefore+size)
	}
	if got := counterValue(t, "homeproxy_bytes_down_total"); got != downBefore+size {
		t.Errorf("homeproxy_bytes_down_total = %v, want %v", got, downBefore+size)
	}
}

func TestProxyCountsForwardedRequestAndResponseBytes(t *testing.T) {
	const body = `{"message":"a forwarded body that comes back unchanged"}`

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(w, r.Body)
	}))
	defer target.Close()

	addr := startTestProxyWithConfig(t, testProxyConfig())

	upBefore := counterValue(t, "homeproxy_bytes_up_total")
	downBefore := counterValue(t, "homeproxy_bytes_down_total")

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeAbsoluteFormRequest(t, conn, http.MethodPost, target.URL+"/echo",
		basicAuth(testCredentialName, testCredentialSecret),
		map[string]string{"Content-Type": "application/json"}, body)

	resp := readProxyResponse(t, conn, http.MethodPost)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	echo, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(echo) != body {
		t.Fatalf("echoed body = %q, want %q", echo, body)
	}

	size := float64(len(body))
	waitForCounter(t, "homeproxy_bytes_up_total", func(v float64) bool { return v >= upBefore+size })
	waitForCounter(t, "homeproxy_bytes_down_total", func(v float64) bool { return v >= downBefore+size })

	if got := counterValue(t, "homeproxy_bytes_up_total"); got != upBefore+size {
		t.Errorf("homeproxy_bytes_up_total = %v, want %v", got, upBefore+size)
	}
	if got := counterValue(t, "homeproxy_bytes_down_total"); got != downBefore+size {
		t.Errorf("homeproxy_bytes_down_total = %v, want %v", got, downBefore+size)
	}
}

func TestProxyCountsDialFailures(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dead target: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	addr := startTestProxyWithConfig(t, testProxyConfig())
	before := counterValue(t, "homeproxy_dial_failures_total")

	conn := dialProxy(t, addr)
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	writeConnect(t, conn, deadAddr, basicAuth(testCredentialName, testCredentialSecret))
	if _, status, _ := readResponseHead(t, bufio.NewReader(conn)); status != http.StatusBadGateway {
		t.Fatalf("status = %d, want %d", status, http.StatusBadGateway)
	}

	waitForCounter(t, "homeproxy_dial_failures_total", func(v float64) bool { return v >= before+1 })
}

func TestProxyObservesDialDuration(t *testing.T) {
	targetAddr := startEchoTarget(t)
	addr := startTestProxyWithConfig(t, testProxyConfig())

	before := histogramCount(t, "homeproxy_dial_duration")

	tunnel := openTunnel(t, addr, targetAddr, basicAuth(testCredentialName, testCredentialSecret))
	_ = tunnel.Close()

	waitForHistogramCount(t, "homeproxy_dial_duration", func(v uint64) bool { return v > before })
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

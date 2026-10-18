package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var testBinary string

const validCredentialsConf = `  users:
    - name: phone
      secret: s3cret
  bypass:
    - 127.0.0.1
`

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "homeproxy-test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create temp dir: %v\n", err)
		os.Exit(1)
	}
	testBinary = filepath.Join(dir, "homeproxy")
	build := exec.Command("go", "build", "-o", testBinary, ".")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "build homeproxy: %v\n", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}

	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func TestProcessLogsBothPortsOnStartup(t *testing.T) {
	app := startApp(t)
	app.waitUntilHealthy(t)

	line := app.waitForLine(t, "proxy port", "management port")
	if !strings.Contains(line, fmt.Sprintf("%d", app.proxyPort)) {
		t.Errorf("startup line does not name proxy port %d: %q", app.proxyPort, line)
	}
	if !strings.Contains(line, fmt.Sprintf("%d", app.managementPort)) {
		t.Errorf("startup line does not name management port %d: %q", app.managementPort, line)
	}
}

func TestProcessServesHealth(t *testing.T) {
	app := startApp(t)
	app.waitUntilHealthy(t)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/health", app.managementPort))
	if err != nil {
		t.Fatalf("GET /health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /health status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestProcessServesMetrics(t *testing.T) {
	app := startApp(t)
	app.waitUntilHealthy(t)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", app.managementPort))
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics body: %v", err)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("Content-Type = %q, want text/plain", resp.Header.Get("Content-Type"))
	}
	if !bytes.Contains(body, []byte("# HELP")) {
		t.Errorf("body does not look like Prometheus text output:\n%s", body)
	}
}

func TestProcessMetricsExposeOperatorSurfaces(t *testing.T) {
	app := startApp(t)
	app.waitUntilHealthy(t)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/metrics", app.managementPort))
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read /metrics body: %v", err)
	}

	for _, name := range []string{
		"homeproxy_requests_total",
		"homeproxy_auth_failures_total",
		"homeproxy_bytes_up_total",
		"homeproxy_bytes_down_total",
		"homeproxy_tunnels_active",
		"homeproxy_dial_duration",
		"homeproxy_dial_failures_total",
	} {
		if !bytes.Contains(body, []byte(name)) {
			t.Errorf("/metrics does not expose %s:\n%s", name, body)
		}
	}
}

func TestProcessLogsFinishedTunnelWithoutSecrets(t *testing.T) {
	const responseBody = "tunnel response body"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		_, _ = io.WriteString(w, responseBody)
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	app := startApp(t)
	app.waitUntilHealthy(t)

	authorization := proxyAuthorization("phone", "s3cret")
	conn := dialAppProxy(t, app)
	writeAppConnect(t, conn, targetAddr, authorization)
	br := bufio.NewReader(conn)
	if status, headers := readAppResponseHead(t, br); status != http.StatusOK {
		t.Fatalf("CONNECT status = %d, want %d (headers: %v)", status, http.StatusOK, headers)
	}

	if _, err := fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetAddr); err != nil {
		t.Fatalf("write request through tunnel: %v", err)
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response through tunnel: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != responseBody {
		t.Fatalf("response body = %q, want %q", body, responseBody)
	}
	_ = conn.Close()

	app.waitForLine(t, "proxy tunnel", "credential=phone", "target="+targetAddr,
		"up=", "down=", "duration=", "outcome=ok")

	output := app.output.String()
	if n := strings.Count(output, "proxy tunnel"); n != 1 {
		t.Errorf("found %d proxy tunnel lines, want 1\noutput:\n%s", n, output)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("phone:s3cret"))
	for _, secret := range []string{"s3cret", encoded} {
		if strings.Contains(output, secret) {
			t.Errorf("process output contains credential material %q\noutput:\n%s", secret, output)
		}
	}
	if strings.Contains(output, "Proxy-Authorization") {
		t.Errorf("process output contains the Proxy-Authorization header name\noutput:\n%s", output)
	}
}

func TestProcessLogsForwardedRequestWithoutSecrets(t *testing.T) {
	const responseBody = "forwarded response body"

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, responseBody)
	}))
	defer target.Close()
	targetHost := strings.TrimPrefix(target.URL, "http://")

	app := startApp(t)
	app.waitUntilHealthy(t)

	authorization := proxyAuthorization("phone", "s3cret")
	request, err := http.NewRequest(http.MethodGet, target.URL+"/resource?q=1", nil)
	if err != nil {
		t.Fatalf("build forwarded request: %v", err)
	}
	request.Header.Set("Proxy-Authorization", authorization)

	conn := dialAppProxy(t, app)
	if err := request.WriteProxy(conn); err != nil {
		t.Fatalf("write absolute-form request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), request)
	if err != nil {
		t.Fatalf("read forwarded response: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read forwarded body: %v", err)
	}
	if string(body) != responseBody {
		t.Fatalf("forwarded body = %q, want %q", body, responseBody)
	}
	_ = conn.Close()

	app.waitForLine(t, "proxy request", "credential=phone", "target="+targetHost,
		"up=", "down=", "duration=", "outcome=200")

	output := app.output.String()
	if n := strings.Count(output, "proxy request"); n != 1 {
		t.Errorf("found %d proxy request lines, want 1\noutput:\n%s", n, output)
	}
	encoded := base64.StdEncoding.EncodeToString([]byte("phone:s3cret"))
	for _, secret := range []string{"s3cret", encoded} {
		if strings.Contains(output, secret) {
			t.Errorf("process output contains credential material %q\noutput:\n%s", secret, output)
		}
	}
	if strings.Contains(output, "Proxy-Authorization") {
		t.Errorf("process output contains the Proxy-Authorization header name\noutput:\n%s", output)
	}
}

func TestProcessLogsAuthFailureWithoutSecrets(t *testing.T) {
	app := startApp(t)
	app.waitUntilHealthy(t)

	conn := dialAppProxy(t, app)
	writeAppConnect(t, conn, "example.com:443", "")
	br := bufio.NewReader(conn)
	if status, _ := readAppResponseHead(t, br); status != http.StatusProxyAuthRequired {
		t.Fatalf("CONNECT status = %d, want %d", status, http.StatusProxyAuthRequired)
	}

	line := app.waitForLine(t, "proxy auth failed", "remote=", `name=""`)
	for _, unexpected := range []string{"example.com", http.MethodConnect, "Proxy-Authorization"} {
		if strings.Contains(line, unexpected) {
			t.Errorf("auth failure line contains %q: %q", unexpected, line)
		}
	}

	output := app.output.String()
	encoded := base64.StdEncoding.EncodeToString([]byte("phone:s3cret"))
	for _, secret := range []string{"s3cret", encoded} {
		if strings.Contains(output, secret) {
			t.Errorf("process output contains credential material %q\noutput:\n%s", secret, output)
		}
	}
}

func TestProcessLogsDialFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve dead target: %v", err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	app := startApp(t)
	app.waitUntilHealthy(t)

	conn := dialAppProxy(t, app)
	writeAppConnect(t, conn, deadAddr, proxyAuthorization("phone", "s3cret"))
	br := bufio.NewReader(conn)
	if status, headers := readAppResponseHead(t, br); status != http.StatusBadGateway {
		t.Fatalf("CONNECT status = %d, want %d (headers: %v)", status, http.StatusBadGateway, headers)
	}

	app.waitForLine(t, "proxy tunnel failed", "target="+deadAddr, "outcome=dial-failed")
}

func proxyAuthorization(name, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(name+":"+secret))
}

func dialAppProxy(t *testing.T, app *appProcess) *net.TCPConn {
	t.Helper()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", app.proxyPort), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	return conn.(*net.TCPConn)
}

func writeAppConnect(t *testing.T, conn net.Conn, target, authorization string) {
	t.Helper()

	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if authorization != "" {
		fmt.Fprintf(&request, "Proxy-Authorization: %s\r\n", authorization)
	}
	request.WriteString("\r\n")

	if _, err := io.WriteString(conn, request.String()); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
}

func readAppResponseHead(t *testing.T, br *bufio.Reader) (int, http.Header) {
	t.Helper()

	statusLine, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	fields := strings.Fields(strings.TrimRight(statusLine, "\r\n"))
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
			return status, headers
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			t.Fatalf("malformed header %q", line)
		}
		headers.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
}

type appProcess struct {
	cmd            *exec.Cmd
	output         *lockedBuffer
	proxyPort      int
	managementPort int
	done           chan error
	exited         bool
	waitErr        error
}

func startApp(t *testing.T) *appProcess {
	t.Helper()

	proxyPort, managementPort := freePortPair(t)
	confPath := writeConf(t, proxyPort, managementPort, validCredentialsConf)

	cmd := exec.Command(testBinary, "configFile="+confPath)
	output := &lockedBuffer{}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start homeproxy: %v", err)
	}

	app := &appProcess{
		cmd:            cmd,
		output:         output,
		proxyPort:      proxyPort,
		managementPort: managementPort,
		done:           make(chan error, 1),
	}
	go func() { app.done <- cmd.Wait() }()

	t.Cleanup(func() {
		if app.exited {
			return
		}
		_ = cmd.Process.Kill()
		<-app.done
		app.exited = true
	})

	return app
}

func (a *appProcess) waitUntilHealthy(t *testing.T) {
	t.Helper()

	url := fmt.Sprintf("http://127.0.0.1:%d/health", a.managementPort)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-a.done:
			a.exited = true
			a.waitErr = err
			t.Fatalf("process exited before becoming healthy: %v\noutput:\n%s", err, a.output.String())
		default:
		}

		resp, err := http.Get(url)
		if err == nil {
			healthy := resp.StatusCode == http.StatusOK
			resp.Body.Close()
			if healthy {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("management surface did not become healthy\noutput:\n%s", a.output.String())
}

func (a *appProcess) waitForLine(t *testing.T, parts ...string) string {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(a.output.String(), "\n") {
			matches := true
			for _, part := range parts {
				if !strings.Contains(line, part) {
					matches = false
					break
				}
			}
			if matches {
				return line
			}
		}
		time.Sleep(20 * time.Millisecond)
	}

	t.Fatalf("log line containing %q not found\noutput:\n%s", parts, a.output.String())
	return ""
}

func (a *appProcess) wait(t *testing.T, timeout time.Duration) error {
	t.Helper()

	if a.exited {
		return a.waitErr
	}

	select {
	case a.waitErr = <-a.done:
		a.exited = true
		return a.waitErr
	case <-time.After(timeout):
		t.Fatalf("process did not exit within %v\noutput:\n%s", timeout, a.output.String())
		return nil
	}
}

func freePortPair(t *testing.T) (proxyPort, managementPort int) {
	t.Helper()

	proxyPort = freePort(t)
	managementPort = freePort(t)
	for managementPort == proxyPort {
		managementPort = freePort(t)
	}
	return proxyPort, managementPort
}

func writeConf(t *testing.T, proxyPort, managementPort int, extra string) string {
	t.Helper()

	conf := fmt.Sprintf(`app:
  name: homeproxy-test
logging:
  level: debug
server:
  port: %d
consul:
  enabled: false
metrics:
  enabled: true
homeproxy:
  port: %d
%s`, managementPort, proxyPort, extra)

	confPath := filepath.Join(t.TempDir(), "conf.yml")
	if err := os.WriteFile(confPath, []byte(conf), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return confPath
}

func freePort(t *testing.T) int {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer ln.Close()

	return ln.Addr().(*net.TCPAddr).Port
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestProcessClosesProxyListenerOnSigterm(t *testing.T) {
	app := startApp(t)
	app.waitUntilHealthy(t)

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", app.proxyPort)
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("proxy port not accepting before SIGTERM: %v", err)
	}
	conn.Close()

	if err := app.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}
	if err := app.wait(t, 10*time.Second); err != nil {
		t.Fatalf("process exit = %v, want 0", err)
	}

	if conn, err := net.DialTimeout("tcp", proxyAddr, time.Second); err == nil {
		conn.Close()
		t.Error("proxy port still accepts connections after SIGTERM")
	}
}

func TestProcessRejectsEmptyCredentials(t *testing.T) {
	proxyPort, managementPort := freePortPair(t)

	output := runToExit(t, writeConf(t, proxyPort, managementPort, "  users: []\n"))

	if !strings.Contains(output, "homeproxy.users") {
		t.Errorf("output does not name homeproxy.users:\n%s", output)
	}
	if !strings.Contains(output, "at least one credential") {
		t.Errorf("output does not explain the problem:\n%s", output)
	}
}

func TestProcessRejectsCredentialWithoutSecret(t *testing.T) {
	proxyPort, managementPort := freePortPair(t)

	output := runToExit(t, writeConf(t, proxyPort, managementPort, `  users:
    - name: phone
      secret: ""
`))

	if !strings.Contains(output, "homeproxy.users") {
		t.Errorf("output does not name homeproxy.users:\n%s", output)
	}
	if !strings.Contains(output, "name and secret") {
		t.Errorf("output does not explain the requirement:\n%s", output)
	}
}

func TestProcessRejectsEqualPorts(t *testing.T) {
	port := freePort(t)

	output := runToExit(t, writeConf(t, port, port, validCredentialsConf))

	if !strings.Contains(output, "homeproxy.port") || !strings.Contains(output, "server.port") {
		t.Errorf("output does not name both ports:\n%s", output)
	}
	if !strings.Contains(output, "must differ") {
		t.Errorf("output does not explain the problem:\n%s", output)
	}
}

func runToExit(t *testing.T, confPath string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, testBinary, "configFile="+confPath)
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("process did not exit\noutput:\n%s", out)
	}

	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("run homeproxy: %v\noutput:\n%s", err, out)
	}
	return string(out)
}

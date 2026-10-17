package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

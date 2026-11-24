package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

const (
	processE2EHelperEnv = "MICROPROXY_PROCESS_E2E_HELPER"
	processE2EConfigEnv = "MICROPROXY_PROCESS_E2E_CONFIG"
	processE2EToken     = "e2e-session-secret-token"
)

// TestMicroproxyHelperProcess is not a normal test: the parent re-executes this
// test binary with the helper environment set, then the helper runs the real
// microproxy bootstrap (config load, listeners, session manager and session
// API). This exercises main.run() without building a separate binary.
func TestMicroproxyHelperProcess(t *testing.T) {
	if os.Getenv(processE2EHelperEnv) != "1" {
		t.Skip("helper process only")
	}
	configPath := os.Getenv(processE2EConfigEnv)
	if strings.TrimSpace(configPath) == "" {
		t.Fatal("helper process requires a config path")
	}
	os.Args = []string{"microproxy", "-config", configPath}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "helper microproxy run failed:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// TestProcessStickySessionContract boots the real microproxy process once and
// drives the documented CROWler contract over the real HTTP session API while a
// mock upstream records the credentials actually presented on each new HTTP
// request and CONNECT handshake.
func TestProcessStickySessionContract(t *testing.T) {
	if os.Getenv(processE2EHelperEnv) == "1" {
		t.Skip("helper process")
	}

	httpTarget := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("target-ok"))
	}))
	defer httpTarget.Close()

	tunnelTarget := newPingPongTCPServer(t)
	defer tunnelTarget.Close()

	upstream := newProcessUpstream(t)
	defer upstream.Close()

	// Reserve the child's fixed ports only after the mock servers have taken
	// their own ephemeral ports, then release them immediately before startup.
	ports := reserveTCPPorts(t, 4)
	rotatingPort, stickyPort, apiPort, metricsPort := ports[0], ports[1], ports[2], ports[3]

	cfg := fmt.Sprintf(`
schema_version: "1"
listeners:
  - name: edge-http
    type: http
    address: 127.0.0.1:%d
    provider: rotating
    auth_type: none
    enabled: true
  - name: edge-http-sticky
    type: http
    address: 127.0.0.1:%d
    provider: sticky
    auth_type: none
    enabled: true
providers:
  - name: rotating
    type: http_proxy
    auth:
      type: basic
      username: rotating-user
      password: rotating-pass
    endpoints:
      - url: %s
    capabilities: ["forward_proxy"]
    health:
      enabled: false
  - name: sticky
    type: http_proxy
    auth:
      type: basic
      username: zone-user
      password: zone-pass
    session:
      supported: true
      mode: username_template
      username_template: "{{username}}-session-{{session_id}}"
    endpoints:
      - url: %s
    capabilities: ["forward_proxy"]
    health:
      enabled: false
routing:
  default_provider: rotating
policies:
  - name: allow-default
    type: base
    action: allow
session_control:
  enabled: true
  address: 127.0.0.1:%d
  auth_type: bearer
  bearer_token: %s
  provider: sticky
observability:
  access_log:
    enabled: true
    format: json
  metrics:
    enabled: true
    address: 127.0.0.1:%d
  health_endpoints: {}
`, rotatingPort, stickyPort, upstream.URL(), upstream.URL(), apiPort, processE2EToken, metricsPort)

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(cfg), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	output := &lockedBuffer{}
	cmd := exec.Command(os.Args[0], "-test.run=^TestMicroproxyHelperProcess$")
	cmd.Env = append(os.Environ(),
		processE2EHelperEnv+"=1",
		processE2EConfigEnv+"="+configPath,
	)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start microproxy helper: %v", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	stopped := false
	t.Cleanup(func() {
		if stopped {
			return
		}
		_ = cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-waitCh:
		case <-time.After(15 * time.Second):
			_ = cmd.Process.Kill()
			<-waitCh
		}
	})

	baseAPI := fmt.Sprintf("http://127.0.0.1:%d", apiPort)
	waitForSessionAPI(t, baseAPI, waitCh, output)

	// 1. Repeated sticky HTTP requests use one pinned upstream identity.
	stickyProxyURL := fmt.Sprintf("http://127.0.0.1:%d", stickyPort)
	rotatingProxyURL := fmt.Sprintf("http://127.0.0.1:%d", rotatingPort)
	stickyClient := newE2EProxyClient(t, stickyProxyURL)
	rotatingClient := newE2EProxyClient(t, rotatingProxyURL)

	for i := 0; i < 3; i++ {
		assertProxiedGET(t, stickyClient, httpTarget.URL)
	}
	beforeRotation := upstream.lastUsername("sticky")
	if !strings.HasPrefix(beforeRotation, "zone-user-session-") {
		t.Fatalf("expected rendered sticky username, got %q", beforeRotation)
	}
	for _, username := range upstream.usernamesFor("sticky") {
		if username != beforeRotation {
			t.Fatalf("sticky identity changed without rotation: %q vs %q", username, beforeRotation)
		}
	}

	assertProxiedGET(t, rotatingClient, httpTarget.URL)
	if got := upstream.lastUsername("rotating"); got != "rotating-user" {
		t.Fatalf("non-sticky provider must keep its static username, got %q", got)
	}

	// 2/3. A CONNECT tunnel opened before rotation survives, while a new
	// CONNECT after rotation authenticates with the new identity.
	tunnelConn, tunnelReader := openE2ETunnel(t, stickyProxyURL, tunnelTarget.Addr())
	defer tunnelConn.Close()
	assertPingPong(t, tunnelConn, tunnelReader)
	tunnelUsernameBefore := upstream.lastUsername("sticky")
	if tunnelUsernameBefore != beforeRotation {
		t.Fatalf("CONNECT must use the pinned identity %q, got %q", beforeRotation, tunnelUsernameBefore)
	}

	doSessionAPIRequest(t, http.MethodPost, baseAPI+"/api/v1/sessions/rotate", processE2EToken, "process-job-1", nil, http.StatusOK)
	// The existing tunnel must keep working on its pinned identity while the
	// new HTTP request picks up the newly committed one.
	assertPingPong(t, tunnelConn, tunnelReader)
	assertProxiedGET(t, stickyClient, httpTarget.URL)
	afterFirstRotation := upstream.lastUsername("sticky")
	if afterFirstRotation == beforeRotation {
		t.Fatal("the next request after rotation still used the old identity")
	}
	if !strings.HasPrefix(afterFirstRotation, "zone-user-session-") {
		t.Fatalf("post-rotation identity is not a rendered sticky username: %q", afterFirstRotation)
	}
	assertProxiedGET(t, stickyClient, httpTarget.URL)
	if got := upstream.lastUsername("sticky"); got != afterFirstRotation {
		t.Fatalf("second post-rotation HTTP request used %q, want %q", got, afterFirstRotation)
	}
	newTunnelConn, newTunnelReader := openE2ETunnel(t, stickyProxyURL, tunnelTarget.Addr())
	defer newTunnelConn.Close()
	assertPingPong(t, newTunnelConn, newTunnelReader)
	if got := upstream.lastUsername("sticky"); got != afterFirstRotation {
		t.Fatalf("post-rotation CONNECT used %q, want %q", got, afterFirstRotation)
	}

	// 4. The non-sticky listener is unaffected by rotation.
	assertProxiedGET(t, rotatingClient, httpTarget.URL)
	if got := upstream.lastUsername("rotating"); got != "rotating-user" {
		t.Fatalf("rotation changed the rotating provider to %q", got)
	}

	// 5. A spoofed X-Provider-ID cannot escape the listener binding, and the
	// rotating upstream must not receive the request.
	beforeSpoof := len(upstream.usernamesFor("rotating"))
	req, err := http.NewRequest(http.MethodGet, httpTarget.URL, nil)
	if err != nil {
		t.Fatalf("build spoofed request: %v", err)
	}
	req.Header.Set("X-Provider-ID", "rotating")
	resp, err := stickyClient.Do(req)
	if err != nil {
		t.Fatalf("spoofed provider request: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if len(upstream.usernamesFor("rotating")) != beforeSpoof {
		t.Fatal("spoofed X-Provider-ID reached the non-sticky upstream")
	}
	if got := upstream.lastUsername("sticky"); got != afterFirstRotation {
		t.Fatalf("spoofed request changed sticky identity to %q", got)
	}

	// 6. Authentication, idempotency and body-boundary semantics over the real
	// HTTP API.
	doSessionAPIRequest(t, http.MethodPost, baseAPI+"/api/v1/sessions/rotate", "", "no-auth", nil, http.StatusUnauthorized)
	doSessionAPIRequest(t, http.MethodPost, baseAPI+"/api/v1/sessions/rotate", "wrong-token", "wrong-auth", nil, http.StatusUnauthorized)
	doSessionAPIRequest(t, http.MethodPost, baseAPI+"/api/v1/sessions/rotate", processE2EToken, "", nil, http.StatusBadRequest)
	doSessionAPIRequest(t, http.MethodPost, baseAPI+"/api/v1/sessions/rotate", processE2EToken, "space key", nil, http.StatusBadRequest)
	doSessionAPIRequest(t, http.MethodPost, baseAPI+"/api/v1/sessions/rotate", processE2EToken, "oversized", strings.NewReader(strings.Repeat("x", 8*1024)), http.StatusBadRequest)
	doSessionAPIRequest(t, http.MethodGet, baseAPI+"/api/v1/sessions/rotate", processE2EToken, "", nil, http.StatusMethodNotAllowed)

	replay := doSessionAPIRequest(t, http.MethodPost, baseAPI+"/api/v1/sessions/rotate", processE2EToken, "process-job-1", nil, http.StatusOK)
	if replayed, _ := replay["replayed"].(bool); !replayed {
		t.Fatalf("latest-key replay must set replayed=true: %+v", replay)
	}
	if gen, _ := replay["generation"].(float64); gen != 2 {
		t.Fatalf("replay returned generation %v, want 2", replay["generation"])
	}
	// A replay must not run connection cleanup or disturb an established tunnel.
	assertPingPong(t, newTunnelConn, newTunnelReader)
	doSessionAPIRequest(t, http.MethodPost, baseAPI+"/api/v1/sessions/rotate", processE2EToken, "process-job-2", nil, http.StatusOK)
	assertProxiedGET(t, stickyClient, httpTarget.URL)
	afterSecondRotation := upstream.lastUsername("sticky")
	if afterSecondRotation == afterFirstRotation {
		t.Fatal("second rotation did not produce a new identity")
	}
	stale := doSessionAPIRequest(t, http.MethodPost, baseAPI+"/api/v1/sessions/rotate", processE2EToken, "process-job-1", nil, http.StatusConflict)
	if stale["original_generation"] != float64(2) || stale["current_generation"] != float64(3) {
		t.Fatalf("unexpected stale generations: %+v", stale)
	}
	// The stale request must neither mutate identity nor close the tunnel.
	assertPingPong(t, newTunnelConn, newTunnelReader)
	if got := upstream.lastUsername("sticky"); got != afterSecondRotation {
		t.Fatalf("stale key or replay mutated identity to %q", got)
	}

	// 7. Session status reports only provider/generation.
	status := doSessionAPIRequest(t, http.MethodGet, baseAPI+"/api/v1/sessions/status", processE2EToken, "", nil, http.StatusOK)
	if status["provider"] != "sticky" || status["generation"] != float64(3) {
		t.Fatalf("unexpected status payload: %+v", status)
	}
	if _, present := status["session_id"]; present {
		t.Fatalf("status exposed the session identity: %+v", status)
	}

	// The rotation counters are visible and carry only fixed-vocabulary labels.
	metricsBody := scrapeMetrics(t, fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort))
	for _, want := range []string{
		`microproxy_session_rotations_total{provider="sticky",outcome="rotated"} 2`,
		`microproxy_session_rotations_total{provider="sticky",outcome="replayed"} 1`,
		`microproxy_session_rotations_total{provider="sticky",outcome="stale"} 1`,
		`microproxy_session_rotations_total{provider="sticky",outcome="unauthorized"} 2`,
		`microproxy_upstream_endpoint_attempts_total{provider="sticky",endpoint="127.0.0.1",outcome="success"}`,
	} {
		if !strings.Contains(metricsBody, want) {
			t.Fatalf("expected %q in metrics:\n%s", want, metricsBody)
		}
	}

	// 8. No credential material may leak through logs or metrics.
	sessionID := strings.TrimPrefix(afterSecondRotation, "zone-user-session-")
	for _, secret := range []string{processE2EToken, "zone-user", "zone-pass", "rotating-pass", sessionID} {
		if secret == "" {
			continue
		}
		if strings.Contains(metricsBody, secret) {
			t.Fatalf("metrics leaked credential material %q:\n%s", secret, metricsBody)
		}
	}

	// Graceful shutdown via SIGTERM must complete without an error.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("signal helper: %v", err)
	}
	select {
	case err := <-waitCh:
		stopped = true
		if err != nil {
			t.Fatalf("microproxy exited with error: %v\n%s", err, output.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("microproxy did not shut down after SIGTERM\n%s", output.String())
	}
	logs := output.String()
	if !strings.Contains(logs, "session rotated") {
		t.Fatalf("expected safe rotation audit log, got:\n%s", logs)
	}
	for _, secret := range []string{processE2EToken, "zone-pass", "rotating-pass", sessionID} {
		if secret == "" {
			continue
		}
		if strings.Contains(logs, secret) {
			t.Fatalf("logs leaked credential material %q:\n%s", secret, logs)
		}
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type processUpstream struct {
	server *httptest.Server
	mu     sync.Mutex
	byName map[string][]string
}

func newProcessUpstream(t *testing.T) *processUpstream {
	t.Helper()
	u := &processUpstream{byName: map[string][]string{}}
	u.server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		username, _ := decodeBasicProxyAuth(req.Header.Get("Proxy-Authorization"))
		provider := "rotating"
		if strings.HasPrefix(username, "zone-user-session-") {
			provider = "sticky"
		}
		u.mu.Lock()
		u.byName[provider] = append(u.byName[provider], username)
		u.mu.Unlock()
		if req.Method == http.MethodConnect {
			if username == "" {
				rw.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			relayConnect(rw, req)
			return
		}
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("mock-upstream-ok"))
	}))
	return u
}

func (u *processUpstream) URL() string { return u.server.URL }

func (u *processUpstream) Close() { u.server.Close() }

func (u *processUpstream) usernamesFor(provider string) []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]string{}, u.byName[provider]...)
}

func (u *processUpstream) lastUsername(provider string) string {
	usernames := u.usernamesFor(provider)
	if len(usernames) == 0 {
		return ""
	}
	return usernames[len(usernames)-1]
}

func decodeBasicProxyAuth(header string) (string, string) {
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(strings.TrimPrefix(header, prefix)))
	if err != nil {
		return "", ""
	}
	username, password, _ := strings.Cut(string(decoded), ":")
	return username, password
}

func relayConnect(rw http.ResponseWriter, req *http.Request) {
	target, err := net.DialTimeout("tcp", req.Host, 3*time.Second)
	if err != nil {
		http.Error(rw, "mock upstream connect failed", http.StatusBadGateway)
		return
	}
	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		_ = target.Close()
		http.Error(rw, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hijacker.Hijack()
	if err != nil {
		_ = target.Close()
		return
	}
	defer client.Close()
	defer target.Close()
	_, _ = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(target, client)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(client, target)
		done <- struct{}{}
	}()
	<-done
}

type pingPongTCPServer struct {
	listener net.Listener
	done     chan struct{}
	wg       sync.WaitGroup
}

func newPingPongTCPServer(t *testing.T) *pingPongTCPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ping-pong target: %v", err)
	}
	server := &pingPongTCPServer{listener: listener, done: make(chan struct{})}
	server.wg.Add(1)
	go func() {
		defer server.wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			server.wg.Add(1)
			go func() {
				defer server.wg.Done()
				defer conn.Close()
				buf := make([]byte, 4)
				for {
					if _, err := io.ReadFull(conn, buf); err != nil {
						return
					}
					if string(buf) == "ping" {
						if _, err := conn.Write([]byte("pong")); err != nil {
							return
						}
					}
				}
			}()
		}
	}()
	return server
}

func (s *pingPongTCPServer) Addr() string {
	return s.listener.Addr().String()
}

func (s *pingPongTCPServer) Close() {
	_ = s.listener.Close()
	select {
	case <-s.done:
	default:
		close(s.done)
	}
	s.wg.Wait()
}

func reserveTCPPorts(t *testing.T, count int) []int {
	t.Helper()
	listeners := make([]net.Listener, 0, count)
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	ports := make([]int, 0, count)
	for i := 0; i < count; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("reserve port: %v", err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, listener.Addr().(*net.TCPAddr).Port)
	}
	return ports
}

func newE2EProxyClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(parsed), DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
}

func assertProxiedGET(t *testing.T, client *http.Client, targetURL string) {
	t.Helper()
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("proxied GET: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxied GET status %d", resp.StatusCode)
	}
}

func openE2ETunnel(t *testing.T, proxyURL, targetAddr string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(proxyURL, "http://"), 3*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr); err != nil {
		_ = conn.Close()
		t.Fatalf("write CONNECT: %v", err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		t.Fatalf("read CONNECT status: %v", err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		_ = conn.Close()
		t.Fatalf("CONNECT failed: %q", statusLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			t.Fatalf("read CONNECT headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	return conn, reader
}

func assertPingPong(t *testing.T, conn net.Conn, reader *bufio.Reader) {
	t.Helper()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write tunnel: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	pong := make([]byte, 4)
	if _, err := io.ReadFull(reader, pong); err != nil {
		t.Fatalf("read tunnel: %v", err)
	}
	if string(pong) != "pong" {
		t.Fatalf("tunnel reply %q", pong)
	}
	_ = conn.SetReadDeadline(time.Time{})
}

func waitForSessionAPI(t *testing.T, baseAPI string, waitCh <-chan error, output *lockedBuffer) {
	t.Helper()
	statusURL := baseAPI + "/api/v1/sessions/status"
	deadline := time.Now().Add(20 * time.Second)
	client := &http.Client{Timeout: time.Second}
	for {
		select {
		case err := <-waitCh:
			t.Fatalf("microproxy exited before becoming ready: %v\n%s", err, output.String())
		default:
		}
		req, _ := http.NewRequest(http.MethodGet, statusURL, nil)
		req.Header.Set("Authorization", "Bearer "+processE2EToken)
		resp, err := client.Do(req)
		if err == nil {
			// Do not drain an unbounded body here: if the reserved port was
			// taken by an unrelated service, reading it could block past the
			// readiness deadline. Status only is enough for this probe.
			statusCode := resp.StatusCode
			resp.Body.Close()
			if statusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("session API did not become ready at %s\n%s", statusURL, output.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func doSessionAPIRequest(t *testing.T, method, url, token, key string, body io.Reader, wantStatus int) map[string]any {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, url, err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	payload := map[string]any{}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&payload)
	if resp.StatusCode != wantStatus {
		t.Fatalf("%s %s: expected %d, got %d: %+v", method, url, wantStatus, resp.StatusCode, payload)
	}
	return payload
}

func scrapeMetrics(t *testing.T, url string) string {
	t.Helper()
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url)
	if err != nil {
		t.Fatalf("scrape metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metrics status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("read metrics: %v", err)
	}
	return string(raw)
}

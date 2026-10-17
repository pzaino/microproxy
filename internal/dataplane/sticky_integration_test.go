package dataplane

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/internal/observability"
	"github.com/pzaino/microproxy/pkg/config"
)

type mockUpstream struct {
	server    *httptest.Server
	mu        sync.Mutex
	usernames []string
	baseUser  string
	basePass  string
}

func newMockUpstream(t *testing.T, baseUser, basePass string) *mockUpstream {
	t.Helper()
	m := &mockUpstream{baseUser: baseUser, basePass: basePass}
	m.server = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		proxyAuth := req.Header.Get("Proxy-Authorization")
		username := decodeProxyUsername(proxyAuth)
		m.mu.Lock()
		m.usernames = append(m.usernames, username)
		m.mu.Unlock()
		if req.Method == http.MethodConnect {
			// Validate CONNECT auth loosely: must be present.
			if proxyAuth == "" {
				rw.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
			handleConnectRelay(rw, req)
			return
		}
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("mock-upstream-ok"))
	}))
	t.Cleanup(m.server.Close)
	return m
}

func decodeProxyUsername(proxyAuth string) string {
	const prefix = "Basic "
	if !strings.HasPrefix(proxyAuth, prefix) {
		return ""
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(proxyAuth, prefix))
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}

func (m *mockUpstream) lastUsername() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.usernames) == 0 {
		return ""
	}
	return m.usernames[len(m.usernames)-1]
}

func (m *mockUpstream) allUsernames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string{}, m.usernames...)
}

func (m *mockUpstream) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usernames = nil
}

func stickyIntegrationConfig(rotatingURL, stickyURL string) *config.Config {
	return &config.Config{
		SchemaVersion: "1",
		Listeners: []config.ListenerConfig{
			{Name: "edge-http", Type: "http", Address: "127.0.0.1:0", AuthType: "none", Enabled: true, Provider: "proxyservice-residential"},
			{Name: "edge-http-sticky", Type: "http", Address: "127.0.0.1:0", AuthType: "none", Enabled: true, Provider: "proxyservice-residential-sticky"},
		},
		Providers: []config.ProviderConfig{
			{
				Name:      "proxyservice-residential",
				Type:      "http_proxy",
				Auth:      config.ProviderAuthConfig{Type: "basic", Username: "rot-user", Password: "rot-pass"},
				Endpoints: []config.ProviderEndpoint{{URL: rotatingURL, Priority: 100}},
				Health:    config.ProviderHealthConfig{Enabled: false},
			},
			{
				Name:      "proxyservice-residential-sticky",
				Type:      "http_proxy",
				Auth:      config.ProviderAuthConfig{Type: "basic", Username: "zone-user", Password: "zone-pass"},
				Endpoints: []config.ProviderEndpoint{{URL: stickyURL, Priority: 100}},
				Session: config.ProviderSessionConfig{
					Supported:        true,
					Mode:             "username_template",
					UsernameTemplate: "{{username}}-session-{{session_id}}",
				},
				Health: config.ProviderHealthConfig{Enabled: false},
			},
		},
		Routing: config.RoutingConfig{
			DefaultProvider: "proxyservice-residential",
			Rules: []config.RoutingRule{
				{Name: "evil-rule", Match: map[string]string{"tenant_id": "evil-tenant"}, Provider: "proxyservice-residential"},
			},
		},
		Policies: []config.PolicyConfig{{Name: "allow-default", Type: "base", Action: "allow"}},
		SessionControl: config.SessionControlConfig{
			Enabled:     true,
			Address:     "127.0.0.1:0",
			BearerToken: "integration-secret",
			Provider:    "proxyservice-residential-sticky",
		},
	}
}

func startStickyPair(t *testing.T, cfg *config.Config, manager *SessionManager) (rotatingURL, stickyURL string, cleanup func()) {
	t.Helper()
	runtime := NewRequestRuntimeWithSessionManager(cfg, manager)
	handler := listeners.NewForwardProxyHandlerWithRuntime(runtime)
	rotating := httptest.NewServer(
		listeners.MetadataMiddleware(
			listeners.ListenerBindingMiddleware("edge-http", "proxyservice-residential",
				observability.HTTPMiddleware(handler, false))),
	)
	sticky := httptest.NewServer(
		listeners.MetadataMiddleware(
			listeners.ListenerBindingMiddleware("edge-http-sticky", "proxyservice-residential-sticky",
				observability.HTTPMiddleware(handler, false))),
	)
	t.Cleanup(rotating.Close)
	t.Cleanup(sticky.Close)
	return rotating.URL, sticky.URL, func() {}
}

func proxyClient(proxyURL string) *http.Client {
	proxyParsed, _ := url.Parse(proxyURL)
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyParsed)}}
}

func TestStickyIntegration_HTTPUsernames(t *testing.T) {
	t.Parallel()
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("target-ok"))
	}))
	defer target.Close()

	rotMock := newMockUpstream(t, "rot-user", "rot-pass")
	stickyMock := newMockUpstream(t, "zone-user", "zone-pass")
	cfg := stickyIntegrationConfig(rotMock.server.URL, stickyMock.server.URL)
	manager, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	rotProxyURL, stickyProxyURL, _ := startStickyPair(t, cfg, manager)

	// 8080 rotating: static username.
	resp, err := proxyClient(rotProxyURL).Get(target.URL)
	if err != nil {
		t.Fatalf("rotating get: %v", err)
	}
	resp.Body.Close()
	if got := rotMock.lastUsername(); got != "rot-user" {
		t.Fatalf("expected rotating username rot-user, got %q", got)
	}

	// 8081 sticky: same username across repeated requests before rotation.
	snapshot, _ := manager.Snapshot("proxyservice-residential-sticky")
	expected, _ := config.RenderUsername("{{username}}-session-{{session_id}}", "zone-user", snapshot.SessionID)
	for i := 0; i < 3; i++ {
		resp, err := proxyClient(stickyProxyURL).Get(target.URL)
		if err != nil {
			t.Fatalf("sticky get %d: %v", i, err)
		}
		resp.Body.Close()
	}
	for _, got := range stickyMock.allUsernames() {
		if got != expected {
			t.Fatalf("expected sticky username %q, got %q", expected, got)
		}
	}

	// Rotation changes sticky, leaves rotating unchanged.
	stickyMock.reset()
	rotMock.reset()
	if _, _, err := manager.Rotate("proxyservice-residential-sticky", "integration-job-1"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	after, _ := manager.Snapshot("proxyservice-residential-sticky")
	expectedAfter, _ := config.RenderUsername("{{username}}-session-{{session_id}}", "zone-user", after.SessionID)
	if expectedAfter == expected {
		t.Fatal("expected new session id after rotation")
	}
	resp, err = proxyClient(stickyProxyURL).Get(target.URL)
	if err != nil {
		t.Fatalf("sticky post-rotate get: %v", err)
	}
	resp.Body.Close()
	if got := stickyMock.lastUsername(); got != expectedAfter {
		t.Fatalf("expected post-rotate %q, got %q", expectedAfter, got)
	}
	resp, err = proxyClient(rotProxyURL).Get(target.URL)
	if err != nil {
		t.Fatalf("rotating post-rotate get: %v", err)
	}
	resp.Body.Close()
	if got := rotMock.lastUsername(); got != "rot-user" {
		t.Fatalf("rotating must remain rot-user, got %q", got)
	}
}

func TestStickyIntegration_CONNECTUsernames(t *testing.T) {
	t.Parallel()
	targetTCP := startPingPongTCPServer(t)
	defer targetTCP.Close()

	rotMock := newMockUpstream(t, "rot-user", "rot-pass")
	stickyMock := newMockUpstream(t, "zone-user", "zone-pass")
	cfg := stickyIntegrationConfig(rotMock.server.URL, stickyMock.server.URL)
	manager, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	_, stickyProxyURL, _ := startStickyPair(t, cfg, manager)

	snapshot, _ := manager.Snapshot("proxyservice-residential-sticky")
	expected, _ := config.RenderUsername("{{username}}-session-{{session_id}}", "zone-user", snapshot.SessionID)

	for i := 0; i < 2; i++ {
		if err := assertConnectPingPong(stickyProxyURL, targetTCP.Addr().String()); err != nil {
			t.Fatalf("connect %d: %v", i, err)
		}
	}
	for _, got := range stickyMock.allUsernames() {
		if got != expected {
			t.Fatalf("expected CONNECT sticky %q, got %q", expected, got)
		}
	}
}

func TestStickyIntegration_MissingSnapshotFailsClosedBeforeUpstream(t *testing.T) {
	t.Parallel()
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("must-not-reach-target"))
	}))
	defer target.Close()
	targetTCP := startPingPongTCPServer(t)
	defer targetTCP.Close()

	rotMock := newMockUpstream(t, "rot-user", "rot-pass")
	stickyMock := newMockUpstream(t, "zone-user", "zone-pass")
	cfg := stickyIntegrationConfig(rotMock.server.URL, stickyMock.server.URL)
	// A manager without provider state cannot pin a sticky identity. The
	// session-enabled adapter must fail closed rather than fall back to the
	// base username or direct egress.
	manager, err := NewSessionManager(&config.Config{SchemaVersion: "1"})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	_, stickyProxyURL, _ := startStickyPair(t, cfg, manager)

	resp, err := proxyClient(stickyProxyURL).Get(target.URL)
	if err != nil {
		t.Fatalf("sticky GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 fail-closed for missing snapshot, got %d: %s", resp.StatusCode, string(body))
	}
	if strings.Contains(string(body), "must-not-reach-target") {
		t.Fatal("missing snapshot leaked a direct egress response")
	}

	proxyAddr := strings.TrimPrefix(stickyProxyURL, "http://")
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	targetAddr := targetTCP.Addr().String()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr); err != nil {
		t.Fatalf("connect write: %v", err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("connect status: %v", err)
	}
	if !strings.Contains(statusLine, "502") {
		t.Fatalf("expected 502 fail-closed CONNECT, got %q", statusLine)
	}
	if usernames := stickyMock.allUsernames(); len(usernames) != 0 {
		t.Fatalf("upstream must not be contacted without a snapshot, got %v", usernames)
	}
}

func TestStickyIntegration_SpoofingBlocked(t *testing.T) {
	t.Parallel()
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok"))
	}))
	defer target.Close()

	rotMock := newMockUpstream(t, "rot-user", "rot-pass")
	stickyMock := newMockUpstream(t, "zone-user", "zone-pass")
	cfg := stickyIntegrationConfig(rotMock.server.URL, stickyMock.server.URL)
	manager, _ := NewSessionManager(cfg)
	_, stickyProxyURL, _ := startStickyPair(t, cfg, manager)

	snapshot, _ := manager.Snapshot("proxyservice-residential-sticky")
	expected, _ := config.RenderUsername("{{username}}-session-{{session_id}}", "zone-user", snapshot.SessionID)

	// Spoofed X-Provider-ID must not escape sticky binding.
	req, _ := http.NewRequest(http.MethodGet, target.URL, nil)
	req.Header.Set("X-Provider-ID", "proxyservice-residential")
	proxyParsed, _ := url.Parse(stickyProxyURL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyParsed)}}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("spoofed provider request: %v", err)
	}
	resp.Body.Close()
	if got := stickyMock.lastUsername(); got != expected {
		t.Fatalf("spoofed X-Provider-ID escaped binding: got %q want %q", got, expected)
	}
	if len(rotMock.allUsernames()) != 0 {
		t.Fatalf("rotating upstream must not be hit via sticky port, got %v", rotMock.allUsernames())
	}

	// Spoofed tenant that matches a rule for the other provider must not reroute.
	stickyMock.reset()
	req2, _ := http.NewRequest(http.MethodGet, target.URL, nil)
	req2.Header.Set("X-Tenant-ID", "evil-tenant")
	resp, err = client.Do(req2)
	if err != nil {
		t.Fatalf("spoofed tenant request: %v", err)
	}
	resp.Body.Close()
	if got := stickyMock.lastUsername(); got != expected {
		t.Fatalf("spoofed tenant escaped binding: got %q want %q", got, expected)
	}
}

func TestStickyIntegration_RequiredUpstreamFailClosed(t *testing.T) {
	t.Parallel()
	// Unknown provider binding must 502, never direct.
	cfg := &config.Config{
		SchemaVersion: "1",
		Listeners: []config.ListenerConfig{
			{Name: "edge", Type: "http", Address: "127.0.0.1:0", Enabled: true, Provider: "missing-provider"},
		},
		Providers: []config.ProviderConfig{
			{Name: "real", Type: "http_proxy", Auth: config.ProviderAuthConfig{Type: "basic", Username: "u", Password: "p"}, Endpoints: []config.ProviderEndpoint{{URL: "http://127.0.0.1:1"}}},
		},
	}
	// Bypass validation for this negative test (missing provider would fail Validate).
	manager, _ := NewSessionManager(cfg)
	runtime := NewRequestRuntimeWithSessionManager(cfg, manager)
	handler := listeners.NewForwardProxyHandlerWithRuntime(runtime)
	server := httptest.NewServer(listeners.MetadataMiddleware(listeners.ListenerBindingMiddleware("edge", "missing-provider", handler)))
	defer server.Close()

	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("must-not-reach-direct"))
	}))
	defer target.Close()

	resp, err := proxyClient(server.URL).Get(target.URL)
	if err != nil {
		t.Fatalf("fail-closed request error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 fail-closed, got %d", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "must-not-reach-direct") {
		t.Fatal("direct egress leaked target body")
	}
}

func TestStickyIntegration_TunnelSurvivesRotation(t *testing.T) {
	t.Parallel()
	targetTCP := startPingPongTCPServer(t)
	defer targetTCP.Close()

	rotMock := newMockUpstream(t, "rot-user", "rot-pass")
	stickyMock := newMockUpstream(t, "zone-user", "zone-pass")
	cfg := stickyIntegrationConfig(rotMock.server.URL, stickyMock.server.URL)
	manager, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	_, stickyProxyURL, _ := startStickyPair(t, cfg, manager)

	proxyAddr := strings.TrimPrefix(stickyProxyURL, "http://")
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	targetAddr := targetTCP.Addr().String()
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr); err != nil {
		t.Fatalf("connect write: %v", err)
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(statusLine, "200") {
		t.Fatalf("connect failed: %q %v", statusLine, err)
	}
	for {
		line, _ := reader.ReadString('\n')
		if line == "\r\n" {
			break
		}
	}
	beforeCount := len(stickyMock.allUsernames())

	// Rotate while tunnel is open.
	if _, _, err := manager.Rotate("proxyservice-residential-sticky", "tunnel-job"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	// Old tunnel must still work.
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write old tunnel: %v", err)
	}
	pong := make([]byte, 4)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(reader, pong); err != nil || string(pong) != "pong" {
		t.Fatalf("old tunnel broken after rotation: %q %v", string(pong), err)
	}

	// New CONNECT must use new identity (one additional upstream auth).
	if err := assertConnectPingPong(stickyProxyURL, targetAddr); err != nil {
		t.Fatalf("new connect: %v", err)
	}
	after := stickyMock.allUsernames()
	if len(after) != beforeCount+1 {
		t.Fatalf("expected exactly one new upstream CONNECT, got %d total (before %d)", len(after), beforeCount)
	}
	if after[len(after)-1] == after[0] {
		t.Fatal("new CONNECT must use new session username")
	}
}

func TestStickyIntegration_ConcurrentTrafficAndRotation(t *testing.T) {
	t.Parallel()
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok"))
	}))
	defer target.Close()

	rotMock := newMockUpstream(t, "rot-user", "rot-pass")
	stickyMock := newMockUpstream(t, "zone-user", "zone-pass")
	cfg := stickyIntegrationConfig(rotMock.server.URL, stickyMock.server.URL)
	manager, _ := NewSessionManager(cfg)
	rotProxyURL, stickyProxyURL, _ := startStickyPair(t, cfg, manager)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errCh := make(chan error, 64)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				resp, err := proxyClient(stickyProxyURL).Get(target.URL)
				if err != nil {
					// Transient port exhaustion under load is environmental;
					// only fail on proxy 502 (fail-closed bug) not dial errors.
					if strings.Contains(err.Error(), "can't assign requested address") {
						time.Sleep(10 * time.Millisecond)
						continue
					}
					errCh <- err
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					errCh <- fmt.Errorf("sticky status %d", resp.StatusCode)
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
		}(i)
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_, _, err := manager.Rotate("proxyservice-residential-sticky", fmt.Sprintf("conc-%d-%d-%d", idx, j, time.Now().UnixNano()))
				if err != nil {
					errCh <- err
					return
				}
				time.Sleep(10 * time.Millisecond)
			}
		}(i)
	}
	// Rotating traffic must stay unaffected.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			resp, err := proxyClient(rotProxyURL).Get(target.URL)
			if err != nil {
				if strings.Contains(err.Error(), "can't assign requested address") {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				errCh <- err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			time.Sleep(5 * time.Millisecond)
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent error: %v", err)
	}
}

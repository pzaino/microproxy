package dataplane

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

func sessionAdapter() httpProxyAdapter {
	return httpProxyAdapter{
		providerName:   "sticky",
		auth:           config.ProviderAuthConfig{Type: "basic", Username: "zone-user", Password: "zone-pass"},
		sessionMode:    "username_template",
		legacyTemplate: "{{username}}-session-{{session_id}}",
		sessionEnabled: true,
	}
}

func TestHTTPProxyAdapter_SessionRendersUsername(t *testing.T) {
	t.Parallel()
	adapter := sessionAdapter()
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := listeners.WithSessionSnapshot(req.Context(), listeners.SessionSnapshot{Provider: "sticky", SessionID: "abc123", Generation: 2})
	req = req.WithContext(ctx)

	prepared, err := adapter.PrepareRequest(req, mustParseURL(t, "http://upstream.example:3128"))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("zone-user-session-abc123:zone-pass"))
	if got := prepared.Header.Get("Proxy-Authorization"); got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestHTTPProxyAdapter_MissingSnapshotFailsClosed(t *testing.T) {
	t.Parallel()
	adapter := sessionAdapter()
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	prepared, err := adapter.PrepareRequest(req, mustParseURL(t, "http://upstream.example:3128"))
	if err == nil {
		t.Fatalf("expected failure without a session snapshot, got %+v", prepared)
	}
	if !strings.Contains(err.Error(), "snapshot is missing") {
		t.Fatalf("expected missing snapshot error, got %v", err)
	}
}

func TestHTTPProxyAdapter_WrongProviderSnapshotFailsClosed(t *testing.T) {
	t.Parallel()
	adapter := sessionAdapter()
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := listeners.WithSessionSnapshot(req.Context(), listeners.SessionSnapshot{Provider: "other", SessionID: "abc123", Generation: 1})
	req = req.WithContext(ctx)
	prepared, err := adapter.PrepareRequest(req, mustParseURL(t, "http://upstream.example:3128"))
	if err == nil {
		t.Fatalf("expected mismatch failure, got %+v", prepared)
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("expected provider mismatch error, got %v", err)
	}
}

func TestHTTPProxyAdapter_RenderFailureFailsClosed(t *testing.T) {
	t.Parallel()
	adapter := sessionAdapter()
	adapter.legacyTemplate = "{{username}}" // invalid: missing {{session_id}}
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := listeners.WithSessionSnapshot(req.Context(), listeners.SessionSnapshot{Provider: "sticky", SessionID: "abc123", Generation: 1})
	req = req.WithContext(ctx)
	prepared, err := adapter.PrepareRequest(req, mustParseURL(t, "http://upstream.example:3128"))
	if err == nil {
		t.Fatalf("expected render failure, got %+v", prepared)
	}
	if !strings.Contains(err.Error(), "render sticky session username") {
		t.Fatalf("expected render error, got %v", err)
	}
}

func TestHTTPProxyAdapter_DialConnectFailsBeforeDialing(t *testing.T) {
	t.Parallel()
	adapter := sessionAdapter()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer upstream.Close()
	endpoint := mustParseURL(t, "http://"+upstream.Addr().String())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	conn, err := adapter.DialConnect(ctx, "example.com:443", endpoint, &net.Dialer{Timeout: time.Second})
	if err == nil {
		conn.Close()
		t.Fatal("expected fail-closed CONNECT without snapshot")
	}
	if !strings.Contains(err.Error(), "snapshot is missing") {
		t.Fatalf("expected session error, got %v", err)
	}
	// No upstream connection may be accepted: set an immediate deadline and
	// verify Accept times out instead of returning a connection.
	tcpListener := upstream.(*net.TCPListener)
	if err := tcpListener.SetDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if accepted, acceptErr := tcpListener.Accept(); acceptErr == nil {
		accepted.Close()
		t.Fatal("upstream was contacted before session validation")
	}
}

func TestHTTPProxyAdapter_SessionDisablesKeepAlives(t *testing.T) {
	t.Parallel()
	endpoint := mustParseURL(t, "http://upstream.example:3128")
	sessionTransport := sessionAdapter().transportFor(endpoint, &http.Transport{}, time.Second)
	if !sessionTransport.DisableKeepAlives {
		t.Fatal("session adapter must disable upstream keep-alives")
	}
	if sessionTransport.MaxIdleConnsPerHost != 0 {
		t.Fatalf("expected no idle upstream connections, got %d", sessionTransport.MaxIdleConnsPerHost)
	}

	staticTransport := httpProxyAdapter{}.transportFor(endpoint, &http.Transport{}, time.Second)
	if staticTransport.DisableKeepAlives {
		t.Fatal("non-session adapter must preserve normal keep-alive behaviour")
	}
}

func TestUpstreamAdapterFactory_SessionAware(t *testing.T) {
	t.Parallel()
	cfg := stickyTestConfig()
	var sticky config.ProviderConfig
	for _, p := range cfg.Providers {
		if p.Name == "sticky" {
			sticky = p
		}
	}
	adapter, ok := upstreamAdapterFactory{}.ForProvider(sticky).(httpProxyAdapter)
	if !ok {
		t.Fatalf("expected httpProxyAdapter, got %T", upstreamAdapterFactory{}.ForProvider(sticky))
	}
	if !adapter.sessionEnabled {
		t.Fatal("expected session-enabled adapter")
	}
	// Static provider must not be session-enabled.
	for _, p := range cfg.Providers {
		if p.Name == "static" {
			staticAdapter, ok := upstreamAdapterFactory{}.ForProvider(p).(httpProxyAdapter)
			if !ok {
				t.Fatalf("expected httpProxyAdapter for static, got %T", upstreamAdapterFactory{}.ForProvider(p))
			}
			if staticAdapter.sessionEnabled {
				t.Fatal("static provider must not be session-enabled")
			}
		}
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	return parsed
}

func TestEffectiveCredentials_PreservesPassword(t *testing.T) {
	t.Parallel()
	adapter := sessionAdapter()
	ctx := listeners.WithSessionSnapshot(context.Background(), listeners.SessionSnapshot{Provider: "sticky", SessionID: strings.Repeat("a", 32), Generation: 5})
	username, password, err := adapter.effectiveCredentials(ctx, mustParseURL(t, "http://upstream.example:3128"))
	if err != nil {
		t.Fatalf("effective credentials: %v", err)
	}
	if password != "zone-pass" {
		t.Fatalf("password must be preserved, got %q", password)
	}
	if !strings.HasPrefix(username, "zone-user-session-") {
		t.Fatalf("unexpected username %q", username)
	}
}

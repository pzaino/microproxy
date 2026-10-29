package dataplane

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/internal/observability"
	"github.com/pzaino/microproxy/pkg/config"
)

// TestRouteResolver_HostFamilyMatch exercises host / host_prefix / host_suffix
// match keys end-to-end through the resolver. Each case uses a focused rule so
// ordering (first-match-wins, the existing contract) is not confounding.
func TestRouteResolver_HostFamilyMatch(t *testing.T) {
	cases := []struct {
		name   string
		rule   config.RoutingRule
		reqURL string
		want   string
	}{
		{
			name:   "host_suffix match routes to rule",
			rule:   config.RoutingRule{Name: "critical", Match: map[string]string{"host_suffix": ".critical.example.com"}, Provider: "critical-p"},
			reqURL: "http://api.critical.example.com/x",
			want:   "critical-p",
		},
		{
			name:   "host_suffix no-match falls through to default",
			rule:   config.RoutingRule{Name: "critical", Match: map[string]string{"host_suffix": ".critical.example.com"}, Provider: "critical-p"},
			reqURL: "http://api.other.example.com/x",
			want:   "default-p",
		},
		{
			name:   "host_prefix match routes to rule",
			rule:   config.RoutingRule{Name: "prefix", Match: map[string]string{"host_prefix": "secure."}, Provider: "prefix-p"},
			reqURL: "http://secure.example.com/y",
			want:   "prefix-p",
		},
		{
			name:   "exact host match routes to rule",
			rule:   config.RoutingRule{Name: "exact", Match: map[string]string{"host": "api.exact-host.example.com"}, Provider: "exact-p"},
			reqURL: "http://api.exact-host.example.com/z",
			want:   "exact-p",
		},
		{
			name:   "no matching rule uses default",
			rule:   config.RoutingRule{Name: "critical", Match: map[string]string{"host_suffix": ".critical.example.com"}, Provider: "critical-p"},
			reqURL: "http://nothing.example.com/q",
			want:   "default-p",
		},
	}
	newResolver := func(rule config.RoutingRule) *RouteResolver {
		cfg := &config.Config{
			Providers: []config.ProviderConfig{
				{Name: "default-p", Type: "direct", Endpoints: []config.ProviderEndpoint{{URL: "http://default.local"}}},
				{Name: "critical-p", Type: "direct", Endpoints: []config.ProviderEndpoint{{URL: "http://critical.local"}}},
				{Name: "prefix-p", Type: "direct", Endpoints: []config.ProviderEndpoint{{URL: "http://prefix.local"}}},
				{Name: "exact-p", Type: "direct", Endpoints: []config.ProviderEndpoint{{URL: "http://exact.local"}}},
			},
			Routing: config.RoutingConfig{
				DefaultProvider: "default-p",
				Rules:           []config.RoutingRule{rule},
			},
		}
		return NewRouteResolver(cfg)
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newResolver(c.rule)
			req, _ := http.NewRequest(http.MethodGet, c.reqURL, nil)
			decision, err := r.Resolve(req, listeners.RequestMetadata{})
			if err != nil {
				t.Fatalf("resolve %q: %v", c.reqURL, err)
			}
			if decision.Provider != c.want {
				t.Fatalf("route for %q = %q, want %q", c.reqURL, decision.Provider, c.want)
			}
		})
	}
}

// TestForProviderEndpoint_RendersCountryRegion confirms that per-endpoint static
// metadata (country/region) flows into the generic credential renderer so a
// credential template can source endpoint.country / endpoint.region per endpoint.
func TestForProviderEndpoint_RendersCountryRegion(t *testing.T) {
	provider := config.ProviderConfig{
		Name: "geo",
		Type: "http_proxy",
		Auth: config.ProviderAuthConfig{
			Type:     "basic",
			Username: "zone",
			Password: "base",
			Templates: config.CredentialTemplates{
				Username: "{{username}}-{{country}}-{{region}}",
			},
			Parameters: map[string]config.CredentialParameter{
				"country": {Source: config.SourceEndpointCountry},
				"region":  {Source: config.SourceEndpointRegion},
			},
		},
		Session:   config.ProviderSessionConfig{Supported: true, Mode: "credential_template", UsernameTemplate: ""},
		Endpoints: []config.ProviderEndpoint{{URL: "http://geo.example:3128", Country: "US", Region: "NY"}},
	}
	adapter, ok := upstreamAdapterFactory{}.ForProviderEndpoint(provider, config.ProviderEndpoint{URL: "http://geo.example:3128", Country: "US", Region: "NY"}).(httpProxyAdapter)
	if !ok {
		t.Fatalf("expected httpProxyAdapter, got %T", upstreamAdapterFactory{}.ForProviderEndpoint(provider, config.ProviderEndpoint{}))
	}
	ctx := listeners.WithSessionSnapshot(context.Background(), listeners.SessionSnapshot{Provider: "geo", SessionID: "sess-1"})
	username, password, err := adapter.effectiveCredentials(ctx, mustURL(t, "http://geo.example:3128"))
	if err != nil {
		t.Fatalf("effectiveCredentials: %v", err)
	}
	if username != "zone-US-NY" {
		t.Fatalf("rendered username = %q, want %q", username, "zone-US-NY")
	}
	if password != "base" {
		t.Fatalf("rendered password = %q, want base %q", password, "base")
	}
}

// TestForProviderEndpoint_MissingCountryFailsClosed confirms that an endpoint
// whose metadata lacks a sourced field fails closed rather than silently
// emitting a credential with an embedded empty value.
func TestForProviderEndpoint_MissingCountryFailsClosed(t *testing.T) {
	provider := config.ProviderConfig{
		Name: "geo",
		Type: "http_proxy",
		Auth: config.ProviderAuthConfig{
			Type:     "basic",
			Username: "zone",
			Password: "base",
			Templates: config.CredentialTemplates{
				Username: "{{username}}-{{country}}",
			},
			Parameters: map[string]config.CredentialParameter{
				"country": {Source: config.SourceEndpointCountry},
			},
		},
		Session: config.ProviderSessionConfig{Supported: true, Mode: "credential_template"},
	}
	// No country on the endpoint metadata.
	adapter := upstreamAdapterFactory{}.ForProviderEndpoint(provider, config.ProviderEndpoint{URL: "http://geo.example:3128"}).(httpProxyAdapter)
	ctx := listeners.WithSessionSnapshot(context.Background(), listeners.SessionSnapshot{Provider: "geo", SessionID: "sess-1"})
	_, _, err := adapter.effectiveCredentials(ctx, mustURL(t, "http://geo.example:3128"))
	if err == nil {
		t.Fatal("expected a missing-country credential to fail closed")
	}
	if !strings.Contains(err.Error(), "country") {
		t.Fatalf("expected a country-source error, got %v", err)
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}

// TestForwardProxy_CredentialTemplate_EndToEnd exercises the full runtime path
// for the generic credential renderer: a credential_template provider whose
// username template sources both the base username and the per-endpoint country
// and the pinned session id. The rendered credential must reach the upstream as
// a basic Proxy-Authorization, and rotation must change the rendered value.
func TestForwardProxy_CredentialTemplate_EndToEnd(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var usernames []string
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		username := decodeProxyUsername(req.Header.Get("Proxy-Authorization"))
		mu.Lock()
		usernames = append(usernames, username)
		mu.Unlock()
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("upstream-ok"))
	}))
	defer upstream.Close()

	provider := config.ProviderConfig{
		Name: "ct-provider",
		Type: "http_proxy",
		Auth: config.ProviderAuthConfig{
			Type:     "basic",
			Username: "zone",
			Password: "basepass",
			Templates: config.CredentialTemplates{
				Username: "{{username}}-{{country}}-{{session_id}}",
			},
			Parameters: map[string]config.CredentialParameter{
				"country": {Source: config.SourceEndpointCountry},
			},
		},
		Endpoints: []config.ProviderEndpoint{{URL: upstream.URL, Priority: 100, Country: "US"}},
		Session:   config.ProviderSessionConfig{Supported: true, Mode: "credential_template"},
		Health:    config.ProviderHealthConfig{Enabled: false},
	}
	cfg := &config.Config{
		SchemaVersion: "1",
		Providers:     []config.ProviderConfig{provider},
		Routing:       config.RoutingConfig{DefaultProvider: "ct-provider"},
		Policies:      []config.PolicyConfig{{Name: "allow", Type: "base", Action: "allow"}},
		SessionControl: config.SessionControlConfig{
			Enabled:     true,
			Address:     "127.0.0.1:0",
			BearerToken: "ct-secret",
			Provider:    "ct-provider",
		},
	}

	manager, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	runtime := NewRequestRuntimeWithSessionManager(cfg, manager)
	handler := listeners.MetadataMiddleware(
		listeners.ListenerBindingMiddleware("edge", "ct-provider",
			observability.HTTPMiddleware(listeners.NewForwardProxyHandlerWithRuntime(runtime), false)),
	)
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	lastName := func() string {
		mu.Lock()
		defer mu.Unlock()
		if len(usernames) == 0 {
			return ""
		}
		return usernames[len(usernames)-1]
	}

	snapshot, _ := manager.Snapshot("ct-provider")
	expected := "zone-US-" + snapshot.SessionID
	resp, err := proxyClient(proxy.URL).Get("http://example.com/")
	if err != nil {
		t.Fatalf("ct forward: %v", err)
	}
	resp.Body.Close()
	if got := lastName(); got != expected {
		t.Fatalf("expected rendered username %q, got %q", expected, got)
	}

	// Rotation changes the pinned session id and therefore the rendered username.
	if _, _, err := manager.Rotate("ct-provider", "ct-job-1"); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	after, _ := manager.Snapshot("ct-provider")
	expectedAfter := "zone-US-" + after.SessionID
	if expectedAfter == expected {
		t.Fatal("expected a new session id after rotation")
	}
	resp, err = proxyClient(proxy.URL).Get("http://example.com/")
	if err != nil {
		t.Fatalf("ct post-rotate forward: %v", err)
	}
	resp.Body.Close()
	if got := lastName(); got != expectedAfter {
		t.Fatalf("expected post-rotate rendered username %q, got %q", expectedAfter, got)
	}
}

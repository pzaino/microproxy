package listeners

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestListenerBindingMiddleware_OverridesClientHeaders(t *testing.T) {
	t.Parallel()
	h := MetadataMiddleware(ListenerBindingMiddleware("edge-http-sticky", "sticky-provider", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		metadata, ok := MetadataFromContext(r.Context())
		if !ok {
			t.Error("expected metadata")
			return
		}
		if metadata.Provider != "sticky-provider" {
			t.Errorf("expected binding to override header, got %q", metadata.Provider)
		}
		if metadata.ListenerName != "edge-http-sticky" {
			t.Errorf("expected listener name, got %q", metadata.ListenerName)
		}
		if metadata.ListenerProvider != "sticky-provider" {
			t.Errorf("expected listener provider, got %q", metadata.ListenerProvider)
		}
		if metadata.TenantID != "spoofed-tenant" {
			t.Errorf("expected tenant passthrough, got %q", metadata.TenantID)
		}
	})))
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Provider-ID", "spoofed-provider")
	req.Header.Set("X-Tenant-ID", "spoofed-tenant")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
}

func TestListenerBindingMiddleware_EmptyPreservesLegacy(t *testing.T) {
	t.Parallel()
	h := MetadataMiddleware(ListenerBindingMiddleware("edge-http", "", http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		metadata, _ := MetadataFromContext(r.Context())
		if metadata.Provider != "client-choice" {
			t.Errorf("expected legacy header passthrough, got %q", metadata.Provider)
		}
	})))
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("X-Provider-ID", "client-choice")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
}

func TestRequiresUpstream(t *testing.T) {
	t.Parallel()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	if RequiresUpstream(req.Context(), "") {
		t.Fatal("expected no required upstream for empty context")
	}
	boundCtx := WithMetadata(context.Background(), RequestMetadata{ListenerProvider: "sticky", Provider: "sticky"})
	if !RequiresUpstream(boundCtx, "sticky") {
		t.Fatal("expected required upstream with binding")
	}
	if !RequiresUpstream(context.Background(), "some-provider") {
		t.Fatal("expected required upstream with provider name")
	}
}

func TestForwardProxy_FailClosedOnRequiredUpstream(t *testing.T) {
	t.Parallel()
	handler := NewForwardProxyHandler()
	handler.Resolver = stubResolver{provider: "missing-provider"}
	handler.Registry = stubRegistry{providers: map[string]RuntimeProvider{}}
	handler.Selector = stubSelectorImpl{}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req = req.WithContext(WithMetadata(req.Context(), RequestMetadata{Provider: "missing-provider"}))
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 fail-closed, got %d", rw.Code)
	}
}

func TestForwardProxy_LegacyDirectStillWorks(t *testing.T) {
	t.Parallel()
	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("direct-ok"))
	}))
	defer target.Close()

	handler := NewForwardProxyHandler()
	handler.Resolver = stubResolver{provider: ""}
	handler.Registry = stubRegistry{providers: map[string]RuntimeProvider{}}
	handler.Selector = stubSelectorImpl{}

	req := httptest.NewRequest(http.MethodGet, target.URL, nil)
	req = req.WithContext(WithMetadata(req.Context(), RequestMetadata{}))
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected legacy direct 200, got %d body %q", rw.Code, rw.Body.String())
	}
}

func TestForwardProxy_BindingEnforcesProvider(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("bound-ok"))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	boundProvider := RuntimeProvider{
		Name:      "sticky",
		Endpoints: []RuntimeEndpoint{{URL: upstreamURL, Adapter: stubAdapter{}}},
	}
	handler := NewForwardProxyHandler()
	handler.Resolver = stubResolver{provider: "spoofed"}
	handler.Registry = stubRegistry{providers: map[string]RuntimeProvider{"sticky": boundProvider}}
	handler.Selector = stubSelectorPassthrough{}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := WithMetadata(req.Context(), RequestMetadata{Provider: "spoofed", TenantID: "t1"})
	UpdateMetadata(ctx, func(m *RequestMetadata) {
		m.ListenerName = "edge-http-sticky"
		m.ListenerProvider = "sticky"
		m.Provider = "sticky"
	})
	req = req.WithContext(ctx)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected bound provider 200, got %d body %q", rw.Code, rw.Body.String())
	}
}

func TestForwardProxy_RouteOverrideBlockedByBinding(t *testing.T) {
	t.Parallel()
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("bound-ok"))
	}))
	defer upstream.Close()
	upstreamURL, _ := url.Parse(upstream.URL)

	boundProvider := RuntimeProvider{Name: "sticky", Endpoints: []RuntimeEndpoint{{URL: upstreamURL, Adapter: stubAdapter{}}}}
	otherProvider := RuntimeProvider{Name: "other", Endpoints: []RuntimeEndpoint{{URL: upstreamURL, Adapter: stubAdapter{}}}}

	handler := NewForwardProxyHandler()
	handler.Resolver = stubResolver{provider: "sticky"}
	handler.Registry = stubRegistry{providers: map[string]RuntimeProvider{"sticky": boundProvider, "other": otherProvider}}
	handler.Selector = stubSelectorPassthrough{}
	handler.PolicyEvaluator = stubPolicy{action: "route_override", override: "other"}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	ctx := WithMetadata(req.Context(), RequestMetadata{Provider: "sticky"})
	UpdateMetadata(ctx, func(m *RequestMetadata) {
		m.ListenerName = "edge-http-sticky"
		m.ListenerProvider = "sticky"
		m.Provider = "sticky"
	})
	req = req.WithContext(ctx)
	rw := httptest.NewRecorder()
	handler.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 with blocked override staying on binding, got %d", rw.Code)
	}
	metadata, _ := MetadataFromContext(req.Context())
	if metadata.Provider != "sticky" {
		t.Fatalf("override must not escape binding, provider=%q", metadata.Provider)
	}
}

type stubResolver struct{ provider string }

func (s stubResolver) Resolve(_ *http.Request, _ RequestMetadata) (RouteDecision, error) {
	return RouteDecision{Provider: s.provider}, nil
}

type stubRegistry struct {
	providers map[string]RuntimeProvider
}

func (s stubRegistry) Get(provider string) (RuntimeProvider, bool) {
	p, ok := s.providers[provider]
	return p, ok
}

type stubSelectorImpl struct{}

func (stubSelectorImpl) Select(_ context.Context, _ RuntimeProvider, _ *http.Request) []RuntimeEndpoint {
	return nil
}

type stubSelectorPassthrough struct{}

func (stubSelectorPassthrough) Select(_ context.Context, provider RuntimeProvider, _ *http.Request) []RuntimeEndpoint {
	return provider.Endpoints
}

type stubAdapter struct{}

func (stubAdapter) PrepareRequest(req *http.Request, _ *url.URL) (*http.Request, error) {
	return req.Clone(req.Context()), nil
}

func (stubAdapter) DialConnect(ctx context.Context, targetAddr string, _ *url.URL, dialer *net.Dialer) (net.Conn, error) {
	return dialer.DialContext(ctx, "tcp", targetAddr)
}

func (stubAdapter) RoundTrip(req *http.Request, _ *url.URL, _ *http.Transport, _ time.Duration) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("bound-ok")),
		Request:    req,
	}, nil
}

func (stubAdapter) RotateIdentity(context.Context) error { return ErrRotateIdentityUnsupported }

func (stubAdapter) Capabilities() []string { return []string{"forward", "connect"} }

type stubPolicy struct {
	action   string
	override string
}

func (s stubPolicy) Evaluate(_ *http.Request, _ RequestMetadata, _ RouteDecision) PolicyDecision {
	if s.action == "" {
		return PolicyDecision{Action: "allow"}
	}
	return PolicyDecision{Action: s.action, RouteOverride: s.override}
}

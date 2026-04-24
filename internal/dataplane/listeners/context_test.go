package listeners

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMetadataMiddleware_UsesHeaders(t *testing.T) {
	t.Parallel()

	h := MetadataMiddleware(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		metadata, ok := MetadataFromContext(r.Context())
		if !ok {
			t.Fatal("expected metadata in request context")
		}
		if metadata.RequestID != "req-123" {
			t.Fatalf("unexpected request ID %q", metadata.RequestID)
		}
		if metadata.TenantID != "tenant-a" {
			t.Fatalf("unexpected tenant ID %q", metadata.TenantID)
		}
		if metadata.Provider != "provider-a" {
			t.Fatalf("unexpected provider %q", metadata.Provider)
		}
	}))

	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	req.Header.Set("X-Request-ID", "req-123")
	req.Header.Set("X-Tenant-ID", "tenant-a")
	req.Header.Set("X-Provider-ID", "provider-a")
	rw := httptest.NewRecorder()

	h.ServeHTTP(rw, req)
}

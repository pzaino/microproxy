package listeners

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestListenerAuthMiddleware_Basic(t *testing.T) {
	t.Parallel()

	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	})
	h := ListenerAuthMiddleware("basic", "user", "pass", next)

	t.Run("rejects missing auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		if rw.Code != http.StatusProxyAuthRequired {
			t.Fatalf("expected %d, got %d", http.StatusProxyAuthRequired, rw.Code)
		}
	})

	t.Run("accepts proxy authorization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
		req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass")))
		rw := httptest.NewRecorder()
		h.ServeHTTP(rw, req)
		if rw.Code != http.StatusNoContent {
			t.Fatalf("expected %d, got %d", http.StatusNoContent, rw.Code)
		}
	})
}

func TestListenerAuthMiddleware_NonePassthrough(t *testing.T) {
	t.Parallel()
	next := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	})
	h := ListenerAuthMiddleware("none", "", "", next)
	req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusNoContent {
		t.Fatalf("expected %d, got %d", http.StatusNoContent, rw.Code)
	}
}

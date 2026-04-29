package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pzaino/microproxy/pkg/config"
)

func TestProviderAsyncLifecycleAndIdempotency(t *testing.T) {
	h := newTestRouter(t, config.NewConfig())
	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/providers", strings.NewReader(`{"provider":{"id":"demo","name":"Demo","type":"http","endpoint":"https://demo.example"}}`))
	withDefaultAuth(createReq)
	h.ServeHTTP(httptest.NewRecorder(), createReq)

	r1 := httptest.NewRequest(http.MethodPost, "/api/v1/providers/demo/rotate", nil)
	r1.Header.Set("Idempotency-Key", "k1")
	withDefaultAuth(r1)
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, r1)
	if w1.Code != http.StatusAccepted {
		t.Fatalf("expected 202 got %d", w1.Code)
	}

	r2 := httptest.NewRequest(http.MethodPost, "/api/v1/providers/demo/rotate", nil)
	r2.Header.Set("Idempotency-Key", "k1")
	withDefaultAuth(r2)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)

	var b1, b2 map[string]AsyncOperation
	_ = json.Unmarshal(w1.Body.Bytes(), &b1)
	_ = json.Unmarshal(w2.Body.Bytes(), &b2)
	if b1["operation"].ID != b2["operation"].ID {
		t.Fatalf("expected idempotent operation id")
	}

	statusReq := httptest.NewRequest(http.MethodGet, "/api/v1/operations/"+b1["operation"].ID, nil)
	withDefaultAuth(statusReq)
	statusRW := httptest.NewRecorder()
	h.ServeHTTP(statusRW, statusReq)
	if statusRW.Code != http.StatusOK {
		t.Fatalf("status expected 200 got %d", statusRW.Code)
	}
}

func TestProviderAsyncFailureMapping(t *testing.T) {
	h := newTestRouter(t, config.NewConfig())
	req := httptest.NewRequest(http.MethodPost, "/api/v1/providers/missing/rotate", nil)
	withDefaultAuth(req)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusNotFound {
		t.Fatalf("expected 404 got %d", rw.Code)
	}
}

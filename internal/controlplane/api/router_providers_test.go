package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pzaino/microproxy/pkg/config"
)

func TestProviderRouterCRUDFlow(t *testing.T) {
	h := newTestRouter(t, config.NewConfig())

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/providers", strings.NewReader(`{"provider":{"id":"demo","name":"Demo","type":"http","endpoint":"https://demo.example"}}`))
	withDefaultAuth(createReq)
	createRW := httptest.NewRecorder()
	h.ServeHTTP(createRW, createReq)
	if createRW.Code != http.StatusCreated {
		t.Fatalf("create: expected 201 got %d", createRW.Code)
	}

	getReq := httptest.NewRequest(http.MethodGet, "/api/v1/providers/demo", nil)
	withDefaultAuth(getReq)
	getRW := httptest.NewRecorder()
	h.ServeHTTP(getRW, getReq)
	if getRW.Code != http.StatusOK {
		t.Fatalf("get: expected 200 got %d", getRW.Code)
	}

	deleteReq := httptest.NewRequest(http.MethodDelete, "/api/v1/providers/demo?resourceVersion=1", nil)
	withDefaultAuth(deleteReq)
	deleteRW := httptest.NewRecorder()
	h.ServeHTTP(deleteRW, deleteReq)
	if deleteRW.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204 got %d", deleteRW.Code)
	}
}

func TestProviderRouterConflictAndValidation(t *testing.T) {
	h := newTestRouter(t, config.NewConfig())

	createReq := httptest.NewRequest(http.MethodPost, "/api/v1/providers", strings.NewReader(`{"provider":{"id":"demo","name":"Demo","type":"http","endpoint":"https://demo.example"}}`))
	withDefaultAuth(createReq)
	h.ServeHTTP(httptest.NewRecorder(), createReq)

	conflictReq := httptest.NewRequest(http.MethodPut, "/api/v1/providers/demo", strings.NewReader(`{"resourceVersion":"99","provider":{"name":"Demo2","type":"http","endpoint":"https://demo.example"}}`))
	withDefaultAuth(conflictReq)
	conflictRW := httptest.NewRecorder()
	h.ServeHTTP(conflictRW, conflictReq)
	if conflictRW.Code != http.StatusConflict {
		t.Fatalf("expected 409 got %d", conflictRW.Code)
	}

	validationReq := httptest.NewRequest(http.MethodPatch, "/api/v1/providers/demo", strings.NewReader(`{"resourceVersion":"1","patch":{"unknown":"x"}}`))
	withDefaultAuth(validationReq)
	validationRW := httptest.NewRecorder()
	h.ServeHTTP(validationRW, validationReq)
	if validationRW.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 got %d", validationRW.Code)
	}

	var conflictBody ErrorEnvelope
	if err := json.Unmarshal(conflictRW.Body.Bytes(), &conflictBody); err != nil {
		t.Fatalf("unmarshal conflict body: %v", err)
	}
	if conflictBody.Error.Code != "version_conflict" {
		t.Fatalf("expected version_conflict got %q", conflictBody.Error.Code)
	}
}

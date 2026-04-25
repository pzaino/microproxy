package api

import (
	"net/http"

	"github.com/pzaino/microproxy/pkg/config"
)

func NewRouter(cfg *config.Config) http.Handler {
	handler, err := NewRouterWithError(cfg)
	if err != nil {
		panic(err)
	}
	return handler
}

func NewRouterWithError(cfg *config.Config) (http.Handler, error) {
	handlers := NewHandlers(cfg)
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/v1/health", handlers.Health)
	mux.HandleFunc("GET /api/v1/config", handlers.Config)

	// Contract-preserving stubs for planned resources.
	mux.HandleFunc("GET /api/v1/providers", handlers.StubCollection("providers"))
	mux.HandleFunc("POST /api/v1/providers", handlers.CreateProvider)
	mux.HandleFunc("GET /api/v1/providers/{providerID}", handlers.StubItem("providers", "providerID"))
	mux.HandleFunc("PUT /api/v1/providers/{providerID}", handlers.ReplaceProvider)
	mux.HandleFunc("PATCH /api/v1/providers/{providerID}", handlers.PatchProvider)
	mux.HandleFunc("DELETE /api/v1/providers/{providerID}", handlers.DeleteProvider)

	mux.HandleFunc("GET /api/v1/policies", handlers.StubCollection("policies"))
	mux.HandleFunc("GET /api/v1/policies/{policyID}", handlers.StubItem("policies", "policyID"))

	mux.HandleFunc("GET /api/v1/routing", handlers.StubCollection("routing"))
	mux.HandleFunc("GET /api/v1/routing/{routeID}", handlers.StubItem("routing", "routeID"))

	mux.HandleFunc("GET /api/v1/tenants", handlers.StubCollection("tenants"))
	mux.HandleFunc("GET /api/v1/tenants/{tenantID}", handlers.StubItem("tenants", "tenantID"))

	mux.HandleFunc("GET /api/v1/sessions", handlers.StubCollection("sessions"))
	mux.HandleFunc("GET /api/v1/sessions/{sessionID}", handlers.StubItem("sessions", "sessionID"))

	authMiddleware, err := newAuthMiddleware()
	if err != nil {
		return nil, err
	}

	return chain(mux,
		panicRecoveryMiddleware,
		requestIDMiddleware,
		authMiddleware,
		loggingMiddleware,
	), nil
}

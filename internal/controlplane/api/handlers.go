package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/pzaino/microproxy/pkg/config"
)

type Handlers struct {
	cfg *config.Config
}

func NewHandlers(cfg *config.Config) *Handlers {
	if cfg == nil {
		cfg = config.NewConfig()
	}
	return &Handlers{cfg: cfg}
}

func (h *Handlers) Health(rw http.ResponseWriter, _ *http.Request) {
	writeJSON(rw, http.StatusOK, HealthResponse{
		Status:    "ok",
		Service:   "microproxy-control",
		Timestamp: time.Now().UTC(),
	})
}

func (h *Handlers) Config(rw http.ResponseWriter, _ *http.Request) {
	writeJSON(rw, http.StatusOK, ConfigResponse{Config: h.cfg})
}

func (h *Handlers) StubCollection(resource string) http.HandlerFunc {
	resource = strings.ToLower(strings.TrimSpace(resource))
	return func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
			return
		}
		writeJSON(rw, http.StatusOK, StubListResponse{Resource: resource, Items: []any{}})
	}
}

func (h *Handlers) StubItem(resource, pathParam string) http.HandlerFunc {
	resource = strings.ToLower(strings.TrimSpace(resource))
	return func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
			return
		}
		itemID := strings.TrimSpace(req.PathValue(pathParam))
		if itemID == "" {
			writeError(rw, http.StatusBadRequest, "invalid_request", "missing resource id", requestIDFromRequest(req))
			return
		}
		writeError(rw, http.StatusNotImplemented, "not_implemented", resource+" item contract is reserved", requestIDFromRequest(req))
	}
}

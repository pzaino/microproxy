package api

import (
	"encoding/json"
	"fmt"
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
	writeJSON(rw, http.StatusOK, ConfigResponse{Config: NewSanitizedConfigView(h.cfg)})
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

func (h *Handlers) CreateProvider(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}
	if err := validateProviderCreateRequest(req); err != nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", err.Error(), requestIDFromRequest(req))
		return
	}
	writeError(rw, http.StatusNotImplemented, "not_implemented", "providers create contract is reserved", requestIDFromRequest(req))
}

func (h *Handlers) ReplaceProvider(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPut {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}
	providerID := strings.TrimSpace(req.PathValue("providerID"))
	if err := validateProviderReplaceRequest(providerID, req); err != nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", err.Error(), requestIDFromRequest(req))
		return
	}
	writeError(rw, http.StatusNotImplemented, "not_implemented", "providers replace contract is reserved", requestIDFromRequest(req))
}

func (h *Handlers) PatchProvider(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPatch {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}
	providerID := strings.TrimSpace(req.PathValue("providerID"))
	if err := validateProviderPatchRequest(providerID, req); err != nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", err.Error(), requestIDFromRequest(req))
		return
	}
	writeError(rw, http.StatusNotImplemented, "not_implemented", "providers patch contract is reserved", requestIDFromRequest(req))
}

func (h *Handlers) DeleteProvider(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodDelete {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}
	providerID := strings.TrimSpace(req.PathValue("providerID"))
	if err := validateProviderDeleteRequest(providerID); err != nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", err.Error(), requestIDFromRequest(req))
		return
	}
	writeError(rw, http.StatusNotImplemented, "not_implemented", "providers delete contract is reserved", requestIDFromRequest(req))
}

func validateProviderCreateRequest(req *http.Request) error {
	return validateJSONBody(req, false)
}

func validateProviderReplaceRequest(providerID string, req *http.Request) error {
	if strings.TrimSpace(providerID) == "" {
		return fmt.Errorf("missing provider id")
	}
	return validateJSONBody(req, false)
}

func validateProviderPatchRequest(providerID string, req *http.Request) error {
	if strings.TrimSpace(providerID) == "" {
		return fmt.Errorf("missing provider id")
	}
	return validateJSONBody(req, true)
}

func validateProviderDeleteRequest(providerID string) error {
	if strings.TrimSpace(providerID) == "" {
		return fmt.Errorf("missing provider id")
	}
	return nil
}

func validateJSONBody(req *http.Request, allowEmpty bool) error {
	if req.Body == nil {
		if allowEmpty {
			return nil
		}
		return fmt.Errorf("request body is required")
	}
	defer req.Body.Close()

	var payload map[string]any
	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		return fmt.Errorf("request body must be valid json object")
	}
	if !allowEmpty && len(payload) == 0 {
		return fmt.Errorf("request body must include at least one field")
	}
	return nil
}

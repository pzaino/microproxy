package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pzaino/microproxy/pkg/config"
)

type Handlers struct {
	cfg           *config.Config
	providerStore ProviderStateStore
}

func NewHandlers(cfg *config.Config) *Handlers {
	if cfg == nil {
		cfg = config.NewConfig()
	}
	return &Handlers{cfg: cfg, providerStore: NewInMemoryProviderStore()}
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

func (h *Handlers) ListProviders(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}
	writeJSON(rw, http.StatusOK, ProviderListResponse{Items: h.providerStore.ListProviders()})
}

func (h *Handlers) GetProvider(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}
	providerID := strings.TrimSpace(req.PathValue("providerID"))
	if providerID == "" {
		writeError(rw, http.StatusBadRequest, "invalid_request", "missing provider id", requestIDFromRequest(req))
		return
	}

	provider, ok := h.providerStore.GetProvider(providerID)
	if !ok {
		writeError(rw, http.StatusNotFound, "not_found", "provider not found", requestIDFromRequest(req))
		return
	}
	writeJSON(rw, http.StatusOK, ProviderResponse{Provider: provider})
}

func (h *Handlers) CreateProvider(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}

	payload, err := decodeProviderWriteRequest(req)
	if err != nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", err.Error(), requestIDFromRequest(req))
		return
	}
	if err := validateProviderSpec(payload.Provider, true); err != nil {
		writeError(rw, http.StatusUnprocessableEntity, "validation_failed", err.Error(), requestIDFromRequest(req))
		return
	}

	provider, err := h.providerStore.CreateProvider(payload.Provider)
	if err != nil {
		switch {
		case errors.Is(err, ErrProviderExists):
			writeError(rw, http.StatusConflict, "resource_conflict", err.Error(), requestIDFromRequest(req))
		default:
			writeError(rw, http.StatusInternalServerError, "internal_error", "failed to create provider", requestIDFromRequest(req))
		}
		return
	}

	writeJSON(rw, http.StatusCreated, ProviderResponse{Provider: provider})
}

func (h *Handlers) ReplaceProvider(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPut {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}
	providerID := strings.TrimSpace(req.PathValue("providerID"))
	if providerID == "" {
		writeError(rw, http.StatusBadRequest, "invalid_request", "missing provider id", requestIDFromRequest(req))
		return
	}

	payload, err := decodeProviderWriteRequest(req)
	if err != nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", err.Error(), requestIDFromRequest(req))
		return
	}
	if payload.ResourceVersion == "" {
		writeError(rw, http.StatusUnprocessableEntity, "validation_failed", "resourceVersion is required", requestIDFromRequest(req))
		return
	}
	payload.Provider.ID = providerID
	if err := validateProviderSpec(payload.Provider, true); err != nil {
		writeError(rw, http.StatusUnprocessableEntity, "validation_failed", err.Error(), requestIDFromRequest(req))
		return
	}

	provider, err := h.providerStore.ReplaceProvider(providerID, payload.ResourceVersion, payload.Provider)
	if err != nil {
		switch {
		case errors.Is(err, ErrProviderNotFound):
			writeError(rw, http.StatusNotFound, "not_found", err.Error(), requestIDFromRequest(req))
		case errors.Is(err, ErrVersionConflict):
			writeError(rw, http.StatusConflict, "version_conflict", err.Error(), requestIDFromRequest(req))
		default:
			writeError(rw, http.StatusInternalServerError, "internal_error", "failed to replace provider", requestIDFromRequest(req))
		}
		return
	}

	writeJSON(rw, http.StatusOK, ProviderResponse{Provider: provider})
}

func (h *Handlers) PatchProvider(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPatch {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}
	providerID := strings.TrimSpace(req.PathValue("providerID"))
	if providerID == "" {
		writeError(rw, http.StatusBadRequest, "invalid_request", "missing provider id", requestIDFromRequest(req))
		return
	}

	payload, err := decodeProviderPatchRequest(req)
	if err != nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", err.Error(), requestIDFromRequest(req))
		return
	}
	if payload.ResourceVersion == "" {
		writeError(rw, http.StatusUnprocessableEntity, "validation_failed", "resourceVersion is required", requestIDFromRequest(req))
		return
	}
	if err := validateProviderPatch(payload.Patch); err != nil {
		writeError(rw, http.StatusUnprocessableEntity, "validation_failed", err.Error(), requestIDFromRequest(req))
		return
	}

	provider, err := h.providerStore.PatchProvider(providerID, payload.ResourceVersion, payload.Patch)
	if err != nil {
		switch {
		case errors.Is(err, ErrProviderNotFound):
			writeError(rw, http.StatusNotFound, "not_found", err.Error(), requestIDFromRequest(req))
		case errors.Is(err, ErrVersionConflict):
			writeError(rw, http.StatusConflict, "version_conflict", err.Error(), requestIDFromRequest(req))
		default:
			writeError(rw, http.StatusInternalServerError, "internal_error", "failed to patch provider", requestIDFromRequest(req))
		}
		return
	}

	writeJSON(rw, http.StatusOK, ProviderResponse{Provider: provider})
}

func (h *Handlers) DeleteProvider(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodDelete {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}
	providerID := strings.TrimSpace(req.PathValue("providerID"))
	if providerID == "" {
		writeError(rw, http.StatusBadRequest, "invalid_request", "missing provider id", requestIDFromRequest(req))
		return
	}
	expectedVersion := strings.TrimSpace(req.URL.Query().Get("resourceVersion"))
	if expectedVersion == "" {
		expectedVersion = strings.TrimSpace(req.Header.Get("If-Match"))
	}
	if expectedVersion == "" {
		writeError(rw, http.StatusUnprocessableEntity, "validation_failed", "resourceVersion is required", requestIDFromRequest(req))
		return
	}

	if err := h.providerStore.DeleteProvider(providerID, expectedVersion); err != nil {
		switch {
		case errors.Is(err, ErrProviderNotFound):
			writeError(rw, http.StatusNotFound, "not_found", err.Error(), requestIDFromRequest(req))
		case errors.Is(err, ErrVersionConflict):
			writeError(rw, http.StatusConflict, "version_conflict", err.Error(), requestIDFromRequest(req))
		default:
			writeError(rw, http.StatusInternalServerError, "internal_error", "failed to delete provider", requestIDFromRequest(req))
		}
		return
	}
	writeNoContent(rw)
}

func decodeProviderWriteRequest(req *http.Request) (ProviderWriteRequest, error) {
	var payload ProviderWriteRequest
	if err := decodeJSONBody(req, &payload); err != nil {
		return ProviderWriteRequest{}, err
	}
	return payload, nil
}

func decodeProviderPatchRequest(req *http.Request) (ProviderPatchRequest, error) {
	var payload ProviderPatchRequest
	if err := decodeJSONBody(req, &payload); err != nil {
		return ProviderPatchRequest{}, err
	}
	return payload, nil
}

func decodeJSONBody(req *http.Request, target any) error {
	if req.Body == nil {
		return fmt.Errorf("request body is required")
	}
	defer req.Body.Close()

	decoder := json.NewDecoder(req.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("request body must be valid json object")
	}
	return nil
}

func validateProviderSpec(spec ProviderSpec, requireAll bool) error {
	if strings.TrimSpace(spec.ID) == "" {
		return fmt.Errorf("provider.id is required")
	}
	if requireAll {
		if strings.TrimSpace(spec.Name) == "" {
			return fmt.Errorf("provider.name is required")
		}
		if strings.TrimSpace(spec.Type) == "" {
			return fmt.Errorf("provider.type is required")
		}
		if strings.TrimSpace(spec.Endpoint) == "" {
			return fmt.Errorf("provider.endpoint is required")
		}
	}
	return nil
}

func validateProviderPatch(patch map[string]any) error {
	if len(patch) == 0 {
		return fmt.Errorf("patch must include at least one supported field")
	}
	for _, field := range []string{"name", "type", "endpoint"} {
		if raw, ok := patch[field]; ok {
			value, ok := raw.(string)
			if !ok {
				return fmt.Errorf("patch.%s must be a string", field)
			}
			if strings.TrimSpace(value) == "" {
				return fmt.Errorf("patch.%s cannot be empty", field)
			}
		}
	}
	for field := range patch {
		switch field {
		case "name", "type", "endpoint":
		default:
			return fmt.Errorf("patch.%s is not supported", field)
		}
	}
	return nil
}

func writeNoContent(rw http.ResponseWriter) {
	rw.WriteHeader(http.StatusNoContent)
}

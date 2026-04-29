package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/pzaino/microproxy/internal/controlplane/runtimeapply"
	"github.com/pzaino/microproxy/internal/dataplane"
	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/internal/dataplane/policy"
	"github.com/pzaino/microproxy/pkg/config"
)

type Handlers struct {
	cfg           *config.Config
	providerStore ProviderStateStore
	resolver      *dataplane.RouteResolver
	registry      *dataplane.ProviderRegistry
	policyEngine  *policy.Engine
	applyManager  *runtimeapply.Manager
	ops           *opStore
}

func NewHandlers(cfg *config.Config) *Handlers {
	if cfg == nil {
		cfg = config.NewConfig()
	}
	store := NewInMemoryProviderStore()
	for _, providerCfg := range cfg.Providers {
		if len(providerCfg.Endpoints) == 0 {
			continue
		}
		_, _ = store.CreateProvider(ProviderSpec{
			ID:       providerCfg.Name,
			Name:     providerCfg.Name,
			Type:     providerCfg.Type,
			Endpoint: providerCfg.Endpoints[0].URL,
		})
	}
	h := &Handlers{
		cfg:           cfg,
		providerStore: store,
		resolver:      dataplane.NewRouteResolver(cfg),
		registry:      dataplane.NewProviderRegistry(cfg),
		policyEngine:  policy.NewEngine(cfg),
		ops:           newOpStore(),
	}
	h.applyManager = runtimeapply.New(cfg, providerStoreAdapter{store: store}, runtimeapply.RuntimeComponents{
		Resolver:         &h.resolver,
		ProviderRegistry: &h.registry,
		PolicyEngine:     &h.policyEngine,
	})
	return h
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
	items := h.providerStore.ListProviders()
	for i := range items {
		items[i].Health = h.providerHealth(items[i].ID)
	}
	writeJSON(rw, http.StatusOK, ProviderListResponse{Items: items})
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
	provider.Health = h.providerHealth(provider.ID)
	writeJSON(rw, http.StatusOK, ProviderResponse{Provider: provider})
}

func (h *Handlers) providerHealth(providerID string) ProviderHealthView {
	if h.registry == nil {
		return ProviderHealthView{}
	}
	endpoints := h.registry.SnapshotProviderHealth(providerID)
	if len(endpoints) == 0 {
		return ProviderHealthView{}
	}
	view := ProviderHealthView{State: "healthy", Endpoints: make([]ProviderEndpointHealth, 0, len(endpoints))}
	for _, endpoint := range endpoints {
		state := string(endpoint.Health.State)
		if state == "" {
			state = "healthy"
		}
		if state != "healthy" && view.State == "healthy" {
			view.State = state
			view.Reason = endpoint.Health.Reason
			view.UpdatedAt = endpoint.Health.UpdatedAt
		}
		view.Endpoints = append(view.Endpoints, ProviderEndpointHealth{
			URL:           endpoint.URL,
			Priority:      endpoint.Priority,
			Weight:        endpoint.Weight,
			State:         state,
			Reason:        endpoint.Health.Reason,
			UpdatedAt:     endpoint.Health.UpdatedAt,
			LastSuccessAt: endpoint.Health.LastSuccessAt,
			LastFailureAt: endpoint.Health.LastFailureAt,
			LastProbeAt:   endpoint.Health.LastProbeAt,
		})
	}
	return view
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

	provider, err := h.applyManager.ApplyProviderMutation(requestIDFromRequest(req), runtimeapply.ProviderMutation{
		Op:   runtimeapply.OpCreateProvider,
		Spec: toRuntimeApplySpec(payload.Provider),
	})
	if err != nil {
		switch {
		case errors.Is(err, ErrProviderExists):
			writeError(rw, http.StatusConflict, "resource_conflict", err.Error(), requestIDFromRequest(req))
		default:
			writeError(rw, http.StatusInternalServerError, "internal_error", "failed to create provider", requestIDFromRequest(req))
		}
		return
	}

	writeJSON(rw, http.StatusCreated, ProviderResponse{Provider: fromRuntimeApplyProvider(provider)})
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

	provider, err := h.applyManager.ApplyProviderMutation(requestIDFromRequest(req), runtimeapply.ProviderMutation{
		Op:              runtimeapply.OpReplaceProvider,
		ProviderID:      providerID,
		ExpectedVersion: payload.ResourceVersion,
		Spec:            toRuntimeApplySpec(payload.Provider),
	})
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

	writeJSON(rw, http.StatusOK, ProviderResponse{Provider: fromRuntimeApplyProvider(provider)})
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

	provider, err := h.applyManager.ApplyProviderMutation(requestIDFromRequest(req), runtimeapply.ProviderMutation{
		Op:              runtimeapply.OpPatchProvider,
		ProviderID:      providerID,
		ExpectedVersion: payload.ResourceVersion,
		Patch:           payload.Patch,
	})
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

	writeJSON(rw, http.StatusOK, ProviderResponse{Provider: fromRuntimeApplyProvider(provider)})
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

	if _, err := h.applyManager.ApplyProviderMutation(requestIDFromRequest(req), runtimeapply.ProviderMutation{
		Op:              runtimeapply.OpDeleteProvider,
		ProviderID:      providerID,
		ExpectedVersion: expectedVersion,
	}); err != nil {
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

func (h *Handlers) PolicyDryRun(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed", requestIDFromRequest(req))
		return
	}
	var payload PolicyDryRunRequest
	if err := decodeJSONBody(req, &payload); err != nil {
		writeError(rw, http.StatusBadRequest, "invalid_request", err.Error(), requestIDFromRequest(req))
		return
	}
	if strings.TrimSpace(payload.PolicyRef) == "" {
		writeError(rw, http.StatusUnprocessableEntity, "validation_failed", "policyRef is required", requestIDFromRequest(req))
		return
	}
	sampleURL := strings.TrimSpace(payload.URL)
	if sampleURL == "" {
		sampleURL = "http://example.local/"
	}
	method := strings.TrimSpace(payload.Method)
	if method == "" {
		method = http.MethodGet
	}
	sampleReq := httptest.NewRequest(method, sampleURL, nil)
	for k, v := range payload.Headers {
		sampleReq.Header.Set(k, v)
	}
	engine := policy.NewEngine(h.cfg)
	decision := engine.Evaluate(sampleReq, listeners.RequestMetadata{
		TenantID:        payload.Metadata.TenantID,
		Provider:        payload.Metadata.Provider,
		ContentType:     payload.Metadata.ContentType,
		RequestSize:     payload.Metadata.RequestSize,
		ResponseSize:    payload.Metadata.ResponseSize,
		EvaluationClock: payload.Metadata.EvaluationTime,
	}, listeners.RouteDecision{
		Provider: payload.Metadata.Provider,
		Policy:   payload.PolicyRef,
		TenantID: payload.Metadata.TenantID,
	})
	writeJSON(rw, http.StatusOK, PolicyDryRunResponse{Decision: decision})
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

type providerStoreAdapter struct{ store ProviderStateStore }

func (a providerStoreAdapter) ListProviders() []runtimeapply.Provider {
	items := a.store.ListProviders()
	out := make([]runtimeapply.Provider, 0, len(items))
	for _, item := range items {
		out = append(out, runtimeapply.Provider{ID: item.ID, ResourceVersion: item.ResourceVersion, Spec: toRuntimeApplySpec(item.Spec)})
	}
	return out
}
func (a providerStoreAdapter) CreateProvider(spec runtimeapply.ProviderSpec) (runtimeapply.Provider, error) {
	p, err := a.store.CreateProvider(fromRuntimeApplySpec(spec))
	return toRuntimeApplyProvider(p), err
}
func (a providerStoreAdapter) ReplaceProvider(id, expectedVersion string, spec runtimeapply.ProviderSpec) (runtimeapply.Provider, error) {
	p, err := a.store.ReplaceProvider(id, expectedVersion, fromRuntimeApplySpec(spec))
	return toRuntimeApplyProvider(p), err
}
func (a providerStoreAdapter) PatchProvider(id, expectedVersion string, patch map[string]any) (runtimeapply.Provider, error) {
	p, err := a.store.PatchProvider(id, expectedVersion, patch)
	return toRuntimeApplyProvider(p), err
}
func (a providerStoreAdapter) DeleteProvider(id, expectedVersion string) error {
	return a.store.DeleteProvider(id, expectedVersion)
}

func toRuntimeApplySpec(spec ProviderSpec) runtimeapply.ProviderSpec {
	return runtimeapply.ProviderSpec{ID: spec.ID, Name: spec.Name, Type: spec.Type, Endpoint: spec.Endpoint}
}
func fromRuntimeApplySpec(spec runtimeapply.ProviderSpec) ProviderSpec {
	return ProviderSpec{ID: spec.ID, Name: spec.Name, Type: spec.Type, Endpoint: spec.Endpoint}
}
func toRuntimeApplyProvider(p Provider) runtimeapply.Provider {
	return runtimeapply.Provider{ID: p.ID, ResourceVersion: p.ResourceVersion, Spec: toRuntimeApplySpec(p.Spec)}
}
func fromRuntimeApplyProvider(p runtimeapply.Provider) Provider {
	return Provider{ID: p.ID, ResourceVersion: p.ResourceVersion, Spec: fromRuntimeApplySpec(p.Spec)}
}

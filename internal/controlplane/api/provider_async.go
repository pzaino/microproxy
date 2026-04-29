package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

type opStore struct {
	mu    sync.Mutex
	byID  map[string]AsyncOperation
	byKey map[string]string
	seq   int
}

func newOpStore() *opStore {
	return &opStore{byID: map[string]AsyncOperation{}, byKey: map[string]string{}}
}
func (s *opStore) create(kind, providerID, sessionID, idem string) AsyncOperation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if idem != "" {
		if id, ok := s.byKey[idem]; ok {
			return s.byID[id]
		}
	}
	s.seq++
	id := fmt.Sprintf("op-%d", s.seq)
	op := AsyncOperation{ID: id, Status: "succeeded", Kind: kind, ProviderID: providerID, SessionID: sessionID}
	s.byID[id] = op
	if idem != "" {
		s.byKey[idem] = id
	}
	return op
}
func (s *opStore) get(id string) (AsyncOperation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.byID[id]
	return op, ok
}

func (h *Handlers) RotateProvider(rw http.ResponseWriter, req *http.Request) {
	pid := strings.TrimSpace(req.PathValue("providerID"))
	if pid == "" {
		writeError(rw, 400, "invalid_request", "missing provider id", requestIDFromRequest(req))
		return
	}
	if _, ok := h.providerStore.GetProvider(pid); !ok {
		writeError(rw, 404, "not_found", "provider not found", requestIDFromRequest(req))
		return
	}
	op := h.ops.create("provider.rotate", pid, "", strings.TrimSpace(req.Header.Get("Idempotency-Key")))
	h.emitAudit(req, "providers.rotate", pid, op, "applied")
	writeJSON(rw, http.StatusAccepted, map[string]any{"operation": op})
}
func (h *Handlers) RefreshProviderSession(rw http.ResponseWriter, req *http.Request) {
	pid := strings.TrimSpace(req.PathValue("providerID"))
	sid := strings.TrimSpace(req.PathValue("sid"))
	if pid == "" || sid == "" {
		writeError(rw, 400, "invalid_request", "missing provider or session id", requestIDFromRequest(req))
		return
	}
	if _, ok := h.providerStore.GetProvider(pid); !ok {
		writeError(rw, 404, "not_found", "provider not found", requestIDFromRequest(req))
		return
	}
	op := h.ops.create("provider.session.refresh", pid, sid, strings.TrimSpace(req.Header.Get("Idempotency-Key")))
	h.emitAudit(req, "providers.rotate", pid, op, "applied")
	writeJSON(rw, http.StatusAccepted, map[string]any{"operation": op})
}
func (h *Handlers) GetProviderCapabilities(rw http.ResponseWriter, req *http.Request) {
	pid := strings.TrimSpace(req.PathValue("providerID"))
	p, ok := h.providerStore.GetProvider(pid)
	if !ok {
		writeError(rw, 404, "not_found", "provider not found", requestIDFromRequest(req))
		return
	}
	writeJSON(rw, http.StatusOK, ProviderCapabilitiesResponse{Capabilities: p.Spec})
}
func (h *Handlers) GetOperationStatus(rw http.ResponseWriter, req *http.Request) {
	opID := strings.TrimSpace(req.PathValue("operationID"))
	op, ok := h.ops.get(opID)
	if !ok {
		writeError(rw, 404, "not_found", "operation not found", requestIDFromRequest(req))
		return
	}
	writeJSON(rw, http.StatusOK, map[string]any{"operation": op})
}

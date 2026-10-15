package dataplane

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/pzaino/microproxy/pkg/config"
)

const (
	sessionAPIMaxBodyBytes = 4 * 1024
	sessionAPIMaxHeaderBytes = 1 << 20
	sessionReadHeaderTimeout = 5 * time.Second
	sessionShutdownDrain = 10 * time.Second
)

// SessionAPIServer is the data-plane-local authenticated management API.
// It mutates the same live SessionManager used by the proxy listeners, not a
// control-plane stub copy.
type SessionAPIServer struct {
	cfg      config.SessionControlConfig
	manager  *SessionManager
	onRotate func()

	mu      sync.Mutex
	started bool
	server  *http.Server
	listener net.Listener
}

// NewSessionAPIServer builds the management server. Returns nil when disabled.
func NewSessionAPIServer(cfg *config.Config, manager *SessionManager, onRotate func()) *SessionAPIServer {
	if cfg == nil || !cfg.SessionControl.Enabled {
		return nil
	}
	control := cfg.SessionControl
	if manager == nil {
		return nil
	}
	mux := http.NewServeMux()
	s := &SessionAPIServer{cfg: control, manager: manager, onRotate: onRotate}
	mux.HandleFunc("/api/v1/sessions/rotate", s.handleRotate)
	mux.HandleFunc("/api/v1/sessions/status", s.handleStatus)
	s.server = &http.Server{
		Addr:              strings.TrimSpace(control.Address),
		Handler:           mux,
		ReadHeaderTimeout: sessionReadHeaderTimeout,
		MaxHeaderBytes:    sessionAPIMaxHeaderBytes,
	}
	return s
}

func (s *SessionAPIServer) Start(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.mu.Unlock()

	if strings.TrimSpace(s.cfg.Address) == "" {
		return errors.New("session_control address is required")
	}
	if strings.TrimSpace(s.cfg.BearerToken) == "" {
		return errors.New("session_control bearer token is required")
	}
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		s.mu.Lock()
		s.started = false
		s.mu.Unlock()
		return fmt.Errorf("listen session api %s: %w", s.server.Addr, err)
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	if host := listenHost(s.server.Addr); !isLoopbackHost(host) {
		slog.Warn("session management API bound to non-loopback address; restrict ingress to a private network", "address", s.server.Addr)
	}

	go func() {
		serveErr := s.server.Serve(listener)
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			slog.Error("session api serve failed", "error", serveErr)
		}
	}()
	_ = ctx
	return nil
}

func (s *SessionAPIServer) Shutdown(ctx context.Context) error {
	if s == nil || s.server == nil {
		return nil
	}
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = false
	s.mu.Unlock()

	shutdownCtx, cancel := context.WithTimeout(ctx, sessionShutdownDrain)
	defer cancel()
	if err := s.server.Shutdown(shutdownCtx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("shutdown session api: %w", err)
	}
	return nil
}

// Addr returns the bound address for tests.
func (s *SessionAPIServer) Addr() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.server.Addr
}

func (s *SessionAPIServer) checkAuth(r *http.Request) bool {
	got := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(r.Header.Get("Authorization")), "Bearer "))
	if got == "" {
		// Only Bearer is accepted; X-API-Key belongs to the control plane.
		return false
	}
	want := s.cfg.BearerToken
	if len(got) != len(want) {
		// Constant-time compare requires equal length; use subtle on padded?
		// Do a dummy compare to avoid early length oracle, then fail.
		_ = subtle.ConstantTimeCompare([]byte(got), []byte(got))
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func (s *SessionAPIServer) handleRotate(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		writeSessionError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method must be POST")
		return
	}
	if !s.checkAuth(req) {
		writeSessionError(rw, http.StatusUnauthorized, "unauthorized", "missing or invalid credentials")
		return
	}
	// Bound body size; rotation takes no payload.
	req.Body = http.MaxBytesReader(rw, req.Body, sessionAPIMaxBodyBytes)
	if _, err := io.Copy(io.Discard, req.Body); err != nil {
		writeSessionError(rw, http.StatusBadRequest, "invalid_request", "request body too large or unreadable")
		return
	}
	_ = req.Body.Close()
	key := strings.TrimSpace(req.Header.Get("Idempotency-Key"))
	if err := ValidateIdempotencyKey(key); err != nil {
		writeSessionError(rw, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	provider := strings.TrimSpace(s.cfg.Provider)
	snapshot, _, err := s.manager.Rotate(provider, key)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "idempotency") || strings.Contains(strings.ToLower(err.Error()), "cannot be empty") || strings.Contains(strings.ToLower(err.Error()), "too long") || strings.Contains(strings.ToLower(err.Error()), "unsupported character") || strings.Contains(strings.ToLower(err.Error()), "printable") {
			writeSessionError(rw, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if strings.Contains(strings.ToLower(err.Error()), "no active session") {
			writeSessionError(rw, http.StatusBadRequest, "invalid_request", "sticky provider has no active session identity")
			return
		}
		// RNG or generation failure: no state change.
		slog.Error("session rotation failed", "provider", provider, "generation_preserved", true)
		writeSessionError(rw, http.StatusServiceUnavailable, "rotation_failed", "failed to generate a new session identity")
		return
	}
	if s.onRotate != nil {
		s.onRotate()
	}
	// Safe audit log: provider + generation only, never identity/username.
	slog.Info("session rotated", "provider", provider, "generation", snapshot.Generation)
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"status":     "rotated",
		"provider":   provider,
		"generation": snapshot.Generation,
	})
}

func (s *SessionAPIServer) handleStatus(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		writeSessionError(rw, http.StatusMethodNotAllowed, "method_not_allowed", "method must be GET")
		return
	}
	if !s.checkAuth(req) {
		writeSessionError(rw, http.StatusUnauthorized, "unauthorized", "missing or invalid credentials")
		return
	}
	provider := strings.TrimSpace(s.cfg.Provider)
	generation, ok := s.manager.Generation(provider)
	if !ok {
		writeSessionError(rw, http.StatusBadRequest, "invalid_request", "sticky provider has no active session identity")
		return
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"provider":   provider,
		"generation": generation,
	})
}

func writeSessionError(rw http.ResponseWriter, status int, code, message string) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": message},
	})
}

func listenHost(addr string) string {
	addr = strings.TrimSpace(addr)
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.TrimSpace(host)
	}
	return addr
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

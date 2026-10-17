package dataplane

import (
	"context"
	"crypto/sha256"
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
	sessionAPIMaxBodyBytes   = 4 * 1024
	sessionAPIMaxHeaderBytes = 1 << 20
	sessionReadHeaderTimeout = 5 * time.Second
	sessionShutdownDrain     = 10 * time.Second
)

// SessionAPIServer is the data-plane-local authenticated management API.
// It mutates the same live SessionManager used by the proxy listeners, not a
// control-plane stub copy.
type SessionAPIServer struct {
	cfg      config.SessionControlConfig
	authType string
	manager  *SessionManager
	onRotate func()

	mu       sync.Mutex
	started  bool
	server   *http.Server
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
	s := &SessionAPIServer{
		cfg:      control,
		authType: control.EffectiveAuthType(),
		manager:  manager,
		onRotate: onRotate,
	}
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

	failStart := func(err error) error {
		s.mu.Lock()
		s.started = false
		s.mu.Unlock()
		return err
	}

	if strings.TrimSpace(s.cfg.Address) == "" {
		return failStart(errors.New("session_control address is required"))
	}
	switch s.authType {
	case config.SessionControlAuthNone:
		if !isLoopbackHost(listenHost(s.server.Addr)) && !s.cfg.AllowUnauthenticatedNonLoopback {
			return failStart(errors.New("session_control auth_type none requires a loopback address; set allow_unauthenticated_non_loopback to expose it on a protected private network"))
		}
	case config.SessionControlAuthBearer:
		if strings.TrimSpace(s.cfg.BearerToken) == "" {
			return failStart(errors.New("session_control bearer token is required when auth_type is bearer"))
		}
	default:
		return failStart(fmt.Errorf("session_control auth_type %q is not supported", s.authType))
	}
	listener, err := net.Listen("tcp", s.server.Addr)
	if err != nil {
		return failStart(fmt.Errorf("listen session api %s: %w", s.server.Addr, err))
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	if host := listenHost(s.server.Addr); !isLoopbackHost(host) {
		if s.authType == config.SessionControlAuthNone {
			slog.Warn("session management API has authentication disabled and is bound to a non-loopback address", "address", s.server.Addr)
		} else {
			slog.Warn("session management API bound to non-loopback address; restrict ingress to a private network", "address", s.server.Addr)
		}
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
	if s.authType == config.SessionControlAuthNone {
		return true
	}
	values := r.Header.Values("Authorization")
	if len(values) != 1 {
		return false
	}
	got, ok := parseBearerCredential(values[0])
	if !ok {
		return false
	}
	want := strings.TrimSpace(s.cfg.BearerToken)
	// Hash both values so the comparison is constant-time regardless of the
	// supplied token length, then compare the fixed-size digests.
	gotDigest := sha256.Sum256([]byte(got))
	wantDigest := sha256.Sum256([]byte(want))
	return subtle.ConstantTimeCompare(gotDigest[:], wantDigest[:]) == 1
}

// parseBearerCredential accepts exactly one "Bearer <token>" credential.
// Missing schemes, empty tokens and extra fields are malformed.
func parseBearerCredential(header string) (string, bool) {
	fields := strings.Fields(header)
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") {
		return "", false
	}
	if fields[1] == "" {
		return "", false
	}
	return fields[1], true
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
	snapshot, replayed, err := s.manager.Rotate(provider, key)
	if err != nil {
		var stale *StaleIdempotencyKeyError
		if errors.As(err, &stale) {
			// The key was committed by an older rotation. Never mutate identity
			// or close upstream connections for a superseded request.
			slog.Info("session rotation rejected as stale idempotency key",
				"provider", provider,
				"original_generation", stale.OriginalGeneration,
				"current_generation", stale.CurrentGeneration,
			)
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"error": map[string]string{
					"code":    "stale_idempotency_key",
					"message": "idempotency key was superseded by a newer rotation",
				},
				"provider":            provider,
				"original_generation": stale.OriginalGeneration,
				"current_generation":  stale.CurrentGeneration,
			})
			return
		}
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
	if replayed {
		// Idempotent replay: the identity and generation are unchanged, so the
		// rotation callback (connection cleanup) must not run again.
		slog.Info("session rotation replayed", "provider", provider, "generation", snapshot.Generation)
	} else {
		if s.onRotate != nil {
			s.onRotate()
		}
		// Safe audit log: provider + generation only, never identity/username.
		slog.Info("session rotated", "provider", provider, "generation", snapshot.Generation)
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusOK)
	payload := map[string]any{
		"status":     "rotated",
		"provider":   provider,
		"generation": snapshot.Generation,
	}
	if replayed {
		payload["replayed"] = true
	}
	_ = json.NewEncoder(rw).Encode(payload)
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
	if host == "" {
		return false
	}
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

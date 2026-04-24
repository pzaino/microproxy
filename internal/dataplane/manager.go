package dataplane

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/internal/observability"
	"github.com/pzaino/microproxy/pkg/config"
)

const defaultDrainTimeout = 15 * time.Second

// ListenerManager controls lifecycle of data-plane listeners.
type ListenerManager interface {
	Start(context.Context) error
	Shutdown(context.Context) error
}

// NoopListenerManager is a bootstrap-safe placeholder manager.
type NoopListenerManager struct{}

func (NoopListenerManager) Start(context.Context) error { return nil }

func (NoopListenerManager) Shutdown(context.Context) error { return nil }

// HTTPListenerManager owns one or more HTTP(S) data-plane listeners.
type HTTPListenerManager struct {
	drainTimeout time.Duration
	handler      *listeners.ForwardProxyHandler

	mu      sync.Mutex
	started bool
	servers []*serverState
}

type serverState struct {
	cfg      config.ListenerConfig
	listener net.Listener
	server   *http.Server

	connMu sync.Mutex
	conns  map[net.Conn]struct{}
}

// NewListenerManager wires the runtime to a concrete listener manager.
// It keeps NoopListenerManager as a fallback when no enabled HTTP listeners exist.
func NewListenerManager(cfg *config.Config) ListenerManager {
	if cfg == nil {
		return NoopListenerManager{}
	}

	httpListeners := make([]config.ListenerConfig, 0, len(cfg.Listeners))
	for _, listenerCfg := range cfg.Listeners {
		if !listenerCfg.Enabled {
			continue
		}
		if listenerCfg.Type == "http" || listenerCfg.Type == "https" {
			httpListeners = append(httpListeners, listenerCfg)
		}
	}
	if len(httpListeners) == 0 {
		return NoopListenerManager{}
	}

	return NewHTTPListenerManager(httpListeners, defaultDrainTimeout, cfg.Observability.AccessLog.Enabled)
}

func NewHTTPListenerManager(listenerConfigs []config.ListenerConfig, drainTimeout time.Duration, accessLogEnabled bool) *HTTPListenerManager {
	if drainTimeout <= 0 {
		drainTimeout = defaultDrainTimeout
	}

	proxyHandler := listeners.NewForwardProxyHandler()
	chain := observability.HTTPMiddleware(listeners.MetadataMiddleware(proxyHandler), accessLogEnabled)

	states := make([]*serverState, 0, len(listenerConfigs))
	for _, listenerCfg := range listenerConfigs {
		server := &http.Server{
			Addr:    listenerCfg.Address,
			Handler: chain,
		}

		state := &serverState{
			cfg:    listenerCfg,
			server: server,
			conns:  make(map[net.Conn]struct{}),
		}

		server.ConnState = state.connState
		states = append(states, state)
	}

	return &HTTPListenerManager{
		drainTimeout: drainTimeout,
		handler:      proxyHandler,
		servers:      states,
	}
}

func (m *HTTPListenerManager) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = true
	m.mu.Unlock()

	for _, state := range m.servers {
		listener, err := net.Listen("tcp", state.cfg.Address)
		if err != nil {
			_ = m.Shutdown(ctx)
			return fmt.Errorf("listen %s (%s): %w", state.cfg.Name, state.cfg.Address, err)
		}
		state.listener = listener

		go func(s *serverState) {
			var serveErr error
			if s.cfg.Type == "https" {
				if s.cfg.TLS == nil {
					serveErr = errors.New("missing tls config")
				} else {
					serveErr = s.server.ServeTLS(s.listener, s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
				}
			} else {
				serveErr = s.server.Serve(s.listener)
			}

			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				_ = s.listener.Close()
			}
		}(state)
	}

	return nil
}

func (m *HTTPListenerManager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = false
	m.mu.Unlock()

	var errs []error
	for _, state := range m.servers {
		shutdownCtx, cancel := context.WithTimeout(ctx, m.drainTimeout)
		err := state.server.Shutdown(shutdownCtx)
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
			errs = append(errs, fmt.Errorf("shutdown %s: %w", state.cfg.Name, err))
		}

		state.closeTrackedConnections()
		if state.listener != nil {
			if err := state.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, fmt.Errorf("close listener %s: %w", state.cfg.Name, err))
			}
		}
	}

	if err := m.handler.Shutdown(ctx); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (s *serverState) connState(conn net.Conn, state http.ConnState) {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	switch state {
	case http.StateNew, http.StateActive, http.StateIdle:
		s.conns[conn] = struct{}{}
	case http.StateHijacked, http.StateClosed:
		delete(s.conns, conn)
	}
}

func (s *serverState) closeTrackedConnections() {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	for conn := range s.conns {
		_ = conn.Close()
		delete(s.conns, conn)
	}
}

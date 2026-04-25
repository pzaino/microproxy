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

// CompositeListenerManager starts/stops a set of concrete listener managers.
type CompositeListenerManager struct {
	managers []ListenerManager
}

func NewCompositeListenerManager(managers ...ListenerManager) *CompositeListenerManager {
	active := make([]ListenerManager, 0, len(managers))
	for _, manager := range managers {
		if manager == nil {
			continue
		}
		active = append(active, manager)
	}
	return &CompositeListenerManager{managers: active}
}

func (m *CompositeListenerManager) Start(ctx context.Context) error {
	started := make([]ListenerManager, 0, len(m.managers))
	for _, manager := range m.managers {
		if err := manager.Start(ctx); err != nil {
			for i := len(started) - 1; i >= 0; i-- {
				_ = started[i].Shutdown(ctx)
			}
			return err
		}
		started = append(started, manager)
	}
	return nil
}

func (m *CompositeListenerManager) Shutdown(ctx context.Context) error {
	var errs []error
	for i := len(m.managers) - 1; i >= 0; i-- {
		if err := m.managers[i].Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

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

// NewListenerManager wires the runtime to concrete listener managers.
func NewListenerManager(cfg *config.Config) ListenerManager {
	if cfg == nil {
		return NoopListenerManager{}
	}

	httpListeners := make([]config.ListenerConfig, 0, len(cfg.Listeners))
	socks5Listeners := make([]config.ListenerConfig, 0, len(cfg.Listeners))
	for _, listenerCfg := range cfg.Listeners {
		if !listenerCfg.Enabled {
			continue
		}
		switch listenerCfg.Type {
		case "http", "https":
			httpListeners = append(httpListeners, listenerCfg)
		case "socks5":
			socks5Listeners = append(socks5Listeners, listenerCfg)
		}
	}

	managers := make([]ListenerManager, 0, 2)
	runtime := NewRequestRuntime(cfg)
	if len(httpListeners) > 0 {
		managers = append(managers, NewHTTPListenerManager(httpListeners, defaultDrainTimeout, cfg.Observability.AccessLog.Enabled, runtime))
	}
	if len(socks5Listeners) > 0 {
		managers = append(managers, NewSOCKS5ListenerManager(socks5Listeners, defaultDrainTimeout, runtime))
	}
	if len(managers) == 0 {
		return NoopListenerManager{}
	}
	return NewCompositeListenerManager(managers...)
}

func NewHTTPListenerManager(listenerConfigs []config.ListenerConfig, drainTimeout time.Duration, accessLogEnabled bool, runtime listeners.RequestRuntime) *HTTPListenerManager {
	if drainTimeout <= 0 {
		drainTimeout = defaultDrainTimeout
	}

	proxyHandler := listeners.NewForwardProxyHandlerWithRuntime(runtime)
	chain := listeners.MetadataMiddleware(observability.HTTPMiddleware(proxyHandler, accessLogEnabled))

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

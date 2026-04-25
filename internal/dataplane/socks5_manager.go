package dataplane

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

// SOCKS5ListenerManager owns one or more SOCKS5 data-plane listeners.
type SOCKS5ListenerManager struct {
	drainTimeout time.Duration
	runtime      listeners.RequestRuntime
	dialer       *net.Dialer

	mu      sync.Mutex
	started bool
	servers []*socks5ServerState
}

type socks5ServerState struct {
	cfg      config.ListenerConfig
	listener net.Listener

	connMu sync.Mutex
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
}

func NewSOCKS5ListenerManager(listenerConfigs []config.ListenerConfig, drainTimeout time.Duration, runtime listeners.RequestRuntime) *SOCKS5ListenerManager {
	if drainTimeout <= 0 {
		drainTimeout = defaultDrainTimeout
	}
	states := make([]*socks5ServerState, 0, len(listenerConfigs))
	for _, listenerCfg := range listenerConfigs {
		states = append(states, &socks5ServerState{cfg: listenerCfg, conns: make(map[net.Conn]struct{})})
	}
	return &SOCKS5ListenerManager{
		drainTimeout: drainTimeout,
		runtime:      runtime,
		dialer:       &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		servers:      states,
	}
}

func (m *SOCKS5ListenerManager) Start(ctx context.Context) error {
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
		go m.serveListener(state)
	}

	return nil
}

func (m *SOCKS5ListenerManager) serveListener(state *socks5ServerState) {
	for {
		conn, err := state.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		state.trackConn(conn)
		state.wg.Add(1)
		go func(clientConn net.Conn) {
			defer state.wg.Done()
			defer state.untrackConn(clientConn)
			defer clientConn.Close()
			m.handleSOCKS5Connection(clientConn, state.cfg)
		}(conn)
	}
}

func (m *SOCKS5ListenerManager) handleSOCKS5Connection(clientConn net.Conn, listenerCfg config.ListenerConfig) {
	authCfg := listeners.SOCKS5AuthConfig{}
	if strings.EqualFold(strings.TrimSpace(listenerCfg.AuthType), "basic") {
		authCfg.Username = listenerCfg.Username
		authCfg.Password = listenerCfg.Password
	}

	req, err := listeners.PerformSOCKS5Handshake(clientConn, authCfg)
	if err != nil {
		return
	}

	targetConn, err := m.dialSOCKS5Target(clientConn, req.Target)
	if err != nil {
		_ = listeners.WriteSOCKS5ConnectReply(clientConn, 0x05, nil)
		return
	}
	defer targetConn.Close()

	if err := listeners.WriteSOCKS5ConnectReply(clientConn, 0x00, targetConn.LocalAddr()); err != nil {
		return
	}

	tunnelConns(clientConn, targetConn)
}

func (m *SOCKS5ListenerManager) dialSOCKS5Target(clientConn net.Conn, targetAddr string) (net.Conn, error) {
	ctx := context.Background()
	if m.runtime.Resolver == nil {
		return m.dialer.DialContext(ctx, "tcp", targetAddr)
	}

	req := (&http.Request{Method: http.MethodConnect, Host: targetAddr, URL: &url.URL{Host: targetAddr}}).WithContext(ctx)
	metadata := listeners.RequestMetadata{}
	decision, err := m.runtime.Resolver.Resolve(req, metadata)
	if err != nil {
		return nil, err
	}
	if decision.Provider == "" || m.runtime.Registry == nil {
		return m.dialer.DialContext(ctx, "tcp", targetAddr)
	}

	provider, ok := m.runtime.Registry.Get(decision.Provider)
	if !ok {
		return nil, fmt.Errorf("provider %q not found", decision.Provider)
	}

	endpoints := provider.Endpoints
	if m.runtime.Selector != nil {
		endpoints = m.runtime.Selector.Select(ctx, provider, req)
	}
	if len(endpoints) == 0 {
		return m.dialer.DialContext(ctx, "tcp", targetAddr)
	}

	var errs []error
	for _, endpoint := range endpoints {
		adapter := endpoint.Adapter
		if adapter == nil {
			adapter = directAdapter{}
		}
		conn, err := adapter.DialConnect(ctx, targetAddr, endpoint.URL, m.dialer)
		if err == nil {
			return conn, nil
		}
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

func (m *SOCKS5ListenerManager) Shutdown(ctx context.Context) error {
	m.mu.Lock()
	if !m.started {
		m.mu.Unlock()
		return nil
	}
	m.started = false
	m.mu.Unlock()

	var errs []error
	for _, state := range m.servers {
		if state.listener != nil {
			if err := state.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, fmt.Errorf("close listener %s: %w", state.cfg.Name, err))
			}
		}
		state.closeTrackedConnections()

		waitCtx, cancel := context.WithTimeout(ctx, m.drainTimeout)
		done := make(chan struct{})
		go func() {
			defer close(done)
			state.wg.Wait()
		}()

		select {
		case <-done:
		case <-waitCtx.Done():
			errs = append(errs, fmt.Errorf("shutdown %s: %w", state.cfg.Name, waitCtx.Err()))
		}
		cancel()
	}

	return errors.Join(errs...)
}

func (s *socks5ServerState) trackConn(conn net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	s.conns[conn] = struct{}{}
}

func (s *socks5ServerState) untrackConn(conn net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	delete(s.conns, conn)
}

func (s *socks5ServerState) closeTrackedConnections() {
	s.connMu.Lock()
	defer s.connMu.Unlock()

	for conn := range s.conns {
		_ = conn.Close()
		delete(s.conns, conn)
	}
}

func tunnelConns(left, right net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(left, right)
		_ = left.SetDeadline(time.Now())
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(right, left)
		_ = right.SetDeadline(time.Now())
	}()
	wg.Wait()
}

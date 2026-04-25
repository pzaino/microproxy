package observability

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

const defaultDrainTimeout = 10 * time.Second

var defaultMetrics = newMetricsStore()

// ListenerManager controls lifecycle of observability listeners.
type ListenerManager interface {
	Start(context.Context) error
	Shutdown(context.Context) error
}

// NoopListenerManager is a bootstrap-safe placeholder manager.
type NoopListenerManager struct{}

func (NoopListenerManager) Start(context.Context) error {
	return nil
}

func (NoopListenerManager) Shutdown(context.Context) error {
	return nil
}

type endpointState struct {
	name     string
	address  string
	listener net.Listener
	server   *http.Server
}

// HTTPListenerManager owns one or more observability HTTP listeners.
type HTTPListenerManager struct {
	drainTimeout time.Duration

	mu      sync.Mutex
	started bool
	servers []*endpointState
}

// NewListenerManager wires the runtime to a concrete observability manager.
func NewListenerManager(cfg *config.Config) ListenerManager {
	if cfg == nil {
		return NoopListenerManager{}
	}

	muxes := map[string]*http.ServeMux{}
	endpointNames := map[string]map[string]struct{}{}

	ensureMux := func(addr string) *http.ServeMux {
		if existing, ok := muxes[addr]; ok {
			return existing
		}
		created := http.NewServeMux()
		muxes[addr] = created
		endpointNames[addr] = map[string]struct{}{}
		return created
	}

	healthCfg := cfg.Observability.HealthEndpoints
	if addr := healthCfg.LivenessAddress; addr != "" {
		mux := ensureMux(addr)
		mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte("ok"))
		})
		endpointNames[addr]["liveness"] = struct{}{}
	}
	if addr := healthCfg.ReadinessAddress; addr != "" {
		mux := ensureMux(addr)
		mux.HandleFunc("/readyz", func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte("ready"))
		})
		endpointNames[addr]["readiness"] = struct{}{}
	}
	if addr := healthCfg.StartupAddress; addr != "" {
		mux := ensureMux(addr)
		mux.HandleFunc("/startupz", func(rw http.ResponseWriter, _ *http.Request) {
			rw.WriteHeader(http.StatusOK)
			_, _ = rw.Write([]byte("started"))
		})
		endpointNames[addr]["startup"] = struct{}{}
	}
	if cfg.Observability.Metrics.Enabled && cfg.Observability.Metrics.Address != "" {
		mux := ensureMux(cfg.Observability.Metrics.Address)
		mux.HandleFunc("/metrics", defaultMetrics.handlePrometheus)
		endpointNames[cfg.Observability.Metrics.Address]["metrics"] = struct{}{}
	}

	if len(muxes) == 0 {
		return NoopListenerManager{}
	}

	states := make([]*endpointState, 0, len(muxes))
	for addr, mux := range muxes {
		nameList := make([]string, 0, len(endpointNames[addr]))
		for name := range endpointNames[addr] {
			nameList = append(nameList, name)
		}
		sort.Strings(nameList)
		states = append(states, &endpointState{
			name:    fmt.Sprintf("observability(%s)", strings.Join(nameList, ",")),
			address: addr,
			server: &http.Server{
				Addr:    addr,
				Handler: mux,
			},
		})
	}

	return &HTTPListenerManager{drainTimeout: defaultDrainTimeout, servers: states}
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
		listener, err := net.Listen("tcp", state.address)
		if err != nil {
			_ = m.Shutdown(ctx)
			return fmt.Errorf("start %s listener on %s: %w", state.name, state.address, err)
		}
		state.listener = listener

		go func(s *endpointState) {
			if err := s.server.Serve(s.listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
				slog.Error("observability listener failed", "endpoint", s.name, "address", s.address, "error", err)
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
			errs = append(errs, fmt.Errorf("shutdown %s: %w", state.name, err))
		}
		if state.listener != nil {
			if err := state.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs = append(errs, fmt.Errorf("close %s listener: %w", state.name, err))
			}
		}
	}

	return errors.Join(errs...)
}

// HTTPMiddleware records baseline metrics and emits structured access logs.
func HTTPMiddleware(next http.Handler, accessLogEnabled bool) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		start := time.Now()
		metadata, _ := listeners.MetadataFromContext(req.Context())
		requestID := valueOrDefault(metadata.RequestID, "unknown")
		rw.Header().Set("X-Request-ID", requestID)

		rec := &statusRecorder{ResponseWriter: rw, statusCode: http.StatusOK}
		next.ServeHTTP(rec, req)

		resolvedMetadata, ok := listeners.MetadataFromContext(req.Context())
		if !ok {
			resolvedMetadata = metadata
		}
		provider := valueOrDefault(resolvedMetadata.Provider, "unknown")
		tenant := valueOrDefault(resolvedMetadata.TenantID, "unknown")

		statusCode := rec.statusCode
		latency := time.Since(start)
		policyAction := valueOrDefault(resolvedMetadata.PolicyAction, "allow")
		policyReason := valueOrDefault(resolvedMetadata.PolicyReason, "none")
		defaultMetrics.observe(req.Method, statusCode, provider, tenant, policyAction, policyReason, latency)

		if accessLogEnabled {
			slog.Info("access",
				"request_id", requestID,
				"provider", provider,
				"tenant", tenant,
				"status", statusCode,
				"latency_ms", latency.Milliseconds(),
				"method", req.Method,
				"path", req.URL.Path,
			)
		}
	})
}

type statusRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.statusCode = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hj, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("hijacking not supported")
	}
	return hj.Hijack()
}

func (r *statusRecorder) Flush() {
	if fl, ok := r.ResponseWriter.(http.Flusher); ok {
		fl.Flush()
	}
}

func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

type histogramState struct {
	bounds []float64
	counts []uint64
	sum    float64
	count  uint64
}

type metricsStore struct {
	mu sync.Mutex

	requestTotal   map[string]uint64
	requestLatency map[string]*histogramState
}

func newMetricsStore() *metricsStore {
	bounds := []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	return &metricsStore{
		requestTotal:   map[string]uint64{},
		requestLatency: map[string]*histogramState{"": {bounds: bounds, counts: make([]uint64, len(bounds)+1)}},
	}
}

func (m *metricsStore) observe(method string, status int, provider, tenant, policyAction, policyReason string, latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	counterKey := fmt.Sprintf("%s|%d|%s|%s|%s|%s", method, status, provider, tenant, policyAction, policyReason)
	m.requestTotal[counterKey]++

	histKey := fmt.Sprintf("%s|%s|%s|%s", method, provider, tenant, policyAction)
	h, ok := m.requestLatency[histKey]
	if !ok {
		bounds := m.requestLatency[""].bounds
		h = &histogramState{bounds: bounds, counts: make([]uint64, len(bounds)+1)}
		m.requestLatency[histKey] = h
	}
	seconds := latency.Seconds()
	h.count++
	h.sum += seconds
	placed := false
	for i, bound := range h.bounds {
		if seconds <= bound {
			h.counts[i]++
			placed = true
			break
		}
	}
	if !placed {
		h.counts[len(h.counts)-1]++
	}
}

func (m *metricsStore) handlePrometheus(rw http.ResponseWriter, _ *http.Request) {
	m.mu.Lock()
	defer m.mu.Unlock()

	rw.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = rw.Write([]byte("# HELP microproxy_http_requests_total Total number of proxied HTTP requests.\n"))
	_, _ = rw.Write([]byte("# TYPE microproxy_http_requests_total counter\n"))

	counterKeys := make([]string, 0, len(m.requestTotal))
	for key := range m.requestTotal {
		counterKeys = append(counterKeys, key)
	}
	sort.Strings(counterKeys)
	for _, key := range counterKeys {
		parts := strings.SplitN(key, "|", 6)
		line := fmt.Sprintf(
			"microproxy_http_requests_total{method=%q,status=%q,provider=%q,tenant=%q,policy_action=%q,policy_reason=%q} %d\n",
			escapeLabel(parts[0]), escapeLabel(parts[1]), escapeLabel(parts[2]), escapeLabel(parts[3]), escapeLabel(parts[4]), escapeLabel(parts[5]), m.requestTotal[key],
		)
		_, _ = rw.Write([]byte(line))
	}
	_, _ = rw.Write([]byte("# HELP microproxy_policy_decisions_total Total number of policy decisions by action and reason.\n"))
	_, _ = rw.Write([]byte("# TYPE microproxy_policy_decisions_total counter\n"))
	for _, key := range counterKeys {
		parts := strings.SplitN(key, "|", 6)
		line := fmt.Sprintf(
			"microproxy_policy_decisions_total{provider=%q,tenant=%q,policy_action=%q,policy_reason=%q} %d\n",
			escapeLabel(parts[2]), escapeLabel(parts[3]), escapeLabel(parts[4]), escapeLabel(parts[5]), m.requestTotal[key],
		)
		_, _ = rw.Write([]byte(line))
	}

	_, _ = rw.Write([]byte("# HELP microproxy_http_request_duration_seconds Latency distribution for proxied HTTP requests.\n"))
	_, _ = rw.Write([]byte("# TYPE microproxy_http_request_duration_seconds histogram\n"))

	histKeys := make([]string, 0, len(m.requestLatency))
	for key := range m.requestLatency {
		if key == "" {
			continue
		}
		histKeys = append(histKeys, key)
	}
	sort.Strings(histKeys)
	for _, key := range histKeys {
		parts := strings.SplitN(key, "|", 4)
		h := m.requestLatency[key]
		cumulative := uint64(0)
		for i, bound := range h.bounds {
			cumulative += h.counts[i]
			_, _ = rw.Write([]byte(fmt.Sprintf(
				"microproxy_http_request_duration_seconds_bucket{method=%q,provider=%q,tenant=%q,policy_action=%q,le=%q} %d\n",
				escapeLabel(parts[0]), escapeLabel(parts[1]), escapeLabel(parts[2]), escapeLabel(parts[3]), trimFloat(bound), cumulative,
			)))
		}
		cumulative += h.counts[len(h.counts)-1]
		_, _ = rw.Write([]byte(fmt.Sprintf(
			"microproxy_http_request_duration_seconds_bucket{method=%q,provider=%q,tenant=%q,policy_action=%q,le=%q} %d\n",
			escapeLabel(parts[0]), escapeLabel(parts[1]), escapeLabel(parts[2]), escapeLabel(parts[3]), "+Inf", cumulative,
		)))
		_, _ = rw.Write([]byte(fmt.Sprintf(
			"microproxy_http_request_duration_seconds_sum{method=%q,provider=%q,tenant=%q,policy_action=%q} %s\n",
			escapeLabel(parts[0]), escapeLabel(parts[1]), escapeLabel(parts[2]), escapeLabel(parts[3]), trimFloat(h.sum),
		)))
		_, _ = rw.Write([]byte(fmt.Sprintf(
			"microproxy_http_request_duration_seconds_count{method=%q,provider=%q,tenant=%q,policy_action=%q} %d\n",
			escapeLabel(parts[0]), escapeLabel(parts[1]), escapeLabel(parts[2]), escapeLabel(parts[3]), h.count,
		)))
	}
}

func escapeLabel(value string) string {
	value = strings.ReplaceAll(value, `\\`, `\\\\`)
	value = strings.ReplaceAll(value, `"`, `\\"`)
	return strings.ReplaceAll(value, "\n", "\\n")
}

func trimFloat(value float64) string {
	if math.IsInf(value, 0) {
		return "+Inf"
	}
	return strconv.FormatFloat(value, 'f', -1, 64)
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

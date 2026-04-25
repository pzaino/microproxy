package listeners

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var hopHeaders = map[string]struct{}{
	"Connection":          {},
	"Proxy-Connection":    {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailer":             {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// RouteDecision captures selected runtime routing details.
type RouteDecision struct {
	TenantID string
	Provider string
	Policy   string
}

// RuntimeEndpoint is an upstream endpoint eligible for selection.
type RuntimeEndpoint struct {
	URL      *url.URL
	Priority int
	Adapter  UpstreamAdapter
	Health   EndpointHealthSnapshot
}

type EndpointHealthSnapshot struct {
	State         string    `json:"state"`
	Reason        string    `json:"reason,omitempty"`
	UpdatedAt     time.Time `json:"updated_at,omitempty"`
	LastSuccessAt time.Time `json:"last_success_at,omitempty"`
	LastFailureAt time.Time `json:"last_failure_at,omitempty"`
	LastProbeAt   time.Time `json:"last_probe_at,omitempty"`
}

// RuntimeProvider is an upstream provider with candidate endpoints.
type RuntimeProvider struct {
	Name      string
	Endpoints []RuntimeEndpoint
}

type TimeoutClassification string

// RouteResolver resolves a provider from request metadata/routing rules.
type RouteResolver interface {
	Resolve(req *http.Request, metadata RequestMetadata) (RouteDecision, error)
}

// ProviderRegistry retrieves provider endpoint definitions by name.
type ProviderRegistry interface {
	Get(provider string) (RuntimeProvider, bool)
}

// EndpointSelector determines ordered endpoint attempts for failover.
type EndpointSelector interface {
	Select(ctx context.Context, provider RuntimeProvider, req *http.Request) []RuntimeEndpoint
}

// TimeoutClassifier classifies timeout failures for observability.
type TimeoutClassifier func(error) TimeoutClassification

// PolicyDecision captures policy evaluation output for a request.
type PolicyDecision struct {
	PolicyName           string
	Action               string
	DenyCode             string
	DenyMessage          string
	DenyCategory         string
	RouteOverride        string
	HeadersPatch         map[string]string
	ResponseHeadersPatch map[string]string
	RedirectURL          string
	RewriteScheme        string
	RewriteHost          string
	RewritePathPrefix    string
	RequestBodyPrefix    string
	ResponseBodyPrefix   string
	Trace                []string
}

// PolicyEvaluator resolves an action for the current request.
type PolicyEvaluator interface {
	Evaluate(req *http.Request, metadata RequestMetadata, route RouteDecision) PolicyDecision
}

// ForwardProxyHandler implements HTTP forward proxying and CONNECT tunneling.
type ForwardProxyHandler struct {
	Transport *http.Transport
	Dialer    *net.Dialer

	Resolver          RouteResolver
	Registry          ProviderRegistry
	Selector          EndpointSelector
	ClassifyTimeoutFn TimeoutClassifier
	PolicyEvaluator   PolicyEvaluator
}

func NewForwardProxyHandler() *ForwardProxyHandler {
	return &ForwardProxyHandler{
		Transport: &http.Transport{
			Proxy:                 nil,
			ForceAttemptHTTP2:     false,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
		},
		Dialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
	}
}

func NewForwardProxyHandlerWithRuntime(runtime RequestRuntime) *ForwardProxyHandler {
	handler := NewForwardProxyHandler()
	handler.Resolver = runtime.Resolver
	handler.Registry = runtime.Registry
	handler.Selector = runtime.Selector
	handler.ClassifyTimeoutFn = runtime.ClassifyTimeoutFn
	handler.PolicyEvaluator = runtime.PolicyEvaluator
	return handler
}

// RequestRuntime bundles runtime routing components.
type RequestRuntime struct {
	Resolver          RouteResolver
	Registry          ProviderRegistry
	Selector          EndpointSelector
	ClassifyTimeoutFn TimeoutClassifier
	PolicyEvaluator   PolicyEvaluator
}

func (h *ForwardProxyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		h.handleConnect(rw, req)
		return
	}

	h.handleForward(rw, req)
}

func (h *ForwardProxyHandler) handleForward(rw http.ResponseWriter, req *http.Request) {
	decision, endpoints, resolved := h.resolveRoute(req)
	metadata, _ := MetadataFromContext(req.Context())
	metadata.ContentType = req.Header.Get("Content-Type")
	metadata.RequestSize = req.ContentLength
	metadata.EvaluationClock = time.Now().UTC()
	if resolved {
		UpdateMetadata(req.Context(), func(metadata *RequestMetadata) {
			if decision.TenantID != "" {
				metadata.TenantID = decision.TenantID
			}
			metadata.Provider = decision.Provider
			metadata.Policy = decision.Policy
		})
	}
	policyDecision := h.evaluatePolicy(req, metadata, decision)
	h.recordPolicyDecision(req.Context(), policyDecision)
	if h.applyDeny(rw, policyDecision) {
		return
	}
	if h.applyRedirect(rw, policyDecision) {
		return
	}
	if policyDecision.Action == "route_override" {
		if overrideEndpoints, ok := h.resolveOverrideEndpoints(req, policyDecision.RouteOverride); ok {
			endpoints = overrideEndpoints
			UpdateMetadata(req.Context(), func(metadata *RequestMetadata) {
				metadata.Provider = policyDecision.RouteOverride
			})
		}
	}

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = req.Host
	}
	removeHopHeaders(outReq.Header)
	if policyDecision.Action == "headers_patch" {
		patchHeaders(outReq.Header, policyDecision.HeadersPatch)
	}
	if policyDecision.Action == "rewrite" {
		applyRewrite(outReq, policyDecision)
	}
	if policyDecision.RequestBodyPrefix != "" && outReq.Body != nil {
		outReq.Body = io.NopCloser(io.MultiReader(strings.NewReader(policyDecision.RequestBodyPrefix), outReq.Body))
	}

	resp, err := h.roundTripWithFallback(outReq, endpoints)
	if err != nil {
		http.Error(rw, fmt.Sprintf("proxy request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	if len(policyDecision.ResponseHeadersPatch) > 0 {
		patchHeaders(resp.Header, policyDecision.ResponseHeadersPatch)
	}
	copyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	if policyDecision.ResponseBodyPrefix != "" {
		_, _ = io.WriteString(rw, policyDecision.ResponseBodyPrefix)
	}
	_, _ = io.Copy(rw, resp.Body)
}

func (h *ForwardProxyHandler) roundTripWithFallback(req *http.Request, endpoints []RuntimeEndpoint) (*http.Response, error) {
	if len(endpoints) == 0 {
		return h.Transport.RoundTrip(req)
	}

	var errs []error
	for i, endpoint := range endpoints {
		adapter := endpoint.Adapter
		if adapter == nil {
			adapter = defaultDirectAdapter{}
		}
		preparedReq, err := adapter.PrepareRequest(req, endpoint.URL)
		if err != nil {
			class := h.classifyTimeout(err)
			h.observeEndpointOutcome(req.Context(), endpoint.URL, err, class)
			errs = append(errs, wrapEndpointError(endpoint.URL, err, class))
			continue
		}
		resp, err := adapter.RoundTrip(preparedReq, endpoint.URL, h.Transport, timeoutForAttempt(h.Dialer.Timeout, i))
		if err == nil {
			h.observeEndpointOutcome(req.Context(), endpoint.URL, nil, "")
			return resp, nil
		}
		class := h.classifyTimeout(err)
		h.observeEndpointOutcome(req.Context(), endpoint.URL, err, class)
		errs = append(errs, wrapEndpointError(endpoint.URL, err, class))
		endpointLabel := "<direct>"
		if endpoint.URL != nil {
			endpointLabel = endpoint.URL.String()
		}
		slog.Warn("forward upstream endpoint failed", "provider", providerFromContext(req.Context()), "endpoint", endpointLabel, "classification", class, "error", err)
	}
	return nil, errors.Join(errs...)
}

func (h *ForwardProxyHandler) handleConnect(rw http.ResponseWriter, req *http.Request) {
	targetAddr, err := canonicalAddress(req.Host)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	decision, endpoints, resolved := h.resolveRoute(req)
	metadata, _ := MetadataFromContext(req.Context())
	metadata.ContentType = req.Header.Get("Content-Type")
	metadata.RequestSize = req.ContentLength
	metadata.EvaluationClock = time.Now().UTC()
	if resolved {
		UpdateMetadata(req.Context(), func(metadata *RequestMetadata) {
			if decision.TenantID != "" {
				metadata.TenantID = decision.TenantID
			}
			metadata.Provider = decision.Provider
			metadata.Policy = decision.Policy
		})
	}
	policyDecision := h.evaluatePolicy(req, metadata, decision)
	h.recordPolicyDecision(req.Context(), policyDecision)
	if h.applyDeny(rw, policyDecision) {
		return
	}
	if h.applyRedirect(rw, policyDecision) {
		return
	}
	if policyDecision.Action == "route_override" {
		if overrideEndpoints, ok := h.resolveOverrideEndpoints(req, policyDecision.RouteOverride); ok {
			endpoints = overrideEndpoints
			UpdateMetadata(req.Context(), func(metadata *RequestMetadata) {
				metadata.Provider = policyDecision.RouteOverride
			})
		}
	}

	var targetConn net.Conn
	if len(endpoints) == 0 {
		targetConn, err = h.Dialer.DialContext(req.Context(), "tcp", targetAddr)
	} else {
		targetConn, err = h.dialConnectViaUpstream(req.Context(), targetAddr, endpoints)
	}
	if err != nil {
		http.Error(rw, fmt.Sprintf("connect target failed: %v", err), http.StatusBadGateway)
		return
	}

	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		targetConn.Close()
		http.Error(rw, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, buffered, err := hijacker.Hijack()
	if err != nil {
		targetConn.Close()
		http.Error(rw, fmt.Sprintf("hijack failed: %v", err), http.StatusInternalServerError)
		return
	}

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		clientConn.Close()
		targetConn.Close()
		return
	}

	if buffered.Reader.Buffered() > 0 {
		if _, err := io.CopyN(targetConn, buffered, int64(buffered.Reader.Buffered())); err != nil {
			clientConn.Close()
			targetConn.Close()
			return
		}
	}

	tunnel(clientConn, targetConn)
}

func (h *ForwardProxyHandler) dialConnectViaUpstream(ctx context.Context, targetAddr string, endpoints []RuntimeEndpoint) (net.Conn, error) {
	var errs []error
	for _, endpoint := range endpoints {
		adapter := endpoint.Adapter
		if adapter == nil {
			adapter = defaultDirectAdapter{}
		}
		conn, err := adapter.DialConnect(ctx, targetAddr, endpoint.URL, h.Dialer)
		if err != nil {
			class := h.classifyTimeout(err)
			h.observeEndpointOutcome(ctx, endpoint.URL, err, class)
			errs = append(errs, wrapEndpointError(endpoint.URL, err, class))
			continue
		}
		h.observeEndpointOutcome(ctx, endpoint.URL, nil, "")
		return conn, nil
	}
	return nil, errors.Join(errs...)
}

func (h *ForwardProxyHandler) observeEndpointOutcome(ctx context.Context, endpoint *url.URL, err error, class TimeoutClassification) {
	type endpointOutcomeRecorder interface {
		ObserveEndpointOutcome(provider string, endpoint *url.URL, err error, class TimeoutClassification)
	}
	recorder, ok := h.Registry.(endpointOutcomeRecorder)
	if !ok {
		return
	}
	metadata, _ := MetadataFromContext(ctx)
	recorder.ObserveEndpointOutcome(metadata.Provider, endpoint, err, class)
}

func (h *ForwardProxyHandler) resolveRoute(req *http.Request) (RouteDecision, []RuntimeEndpoint, bool) {
	metadata, _ := MetadataFromContext(req.Context())
	if h.Resolver == nil {
		return RouteDecision{}, nil, false
	}

	decision, err := h.Resolver.Resolve(req, metadata)
	if err != nil || decision.Provider == "" || h.Registry == nil || h.Selector == nil {
		return decision, nil, err == nil
	}

	provider, ok := h.Registry.Get(decision.Provider)
	if !ok {
		return decision, nil, true
	}
	return decision, h.Selector.Select(req.Context(), provider, req), true
}

func (h *ForwardProxyHandler) resolveOverrideEndpoints(req *http.Request, provider string) ([]RuntimeEndpoint, bool) {
	if provider == "" || h.Registry == nil || h.Selector == nil {
		return nil, false
	}
	runtimeProvider, ok := h.Registry.Get(provider)
	if !ok {
		return nil, false
	}
	return h.Selector.Select(req.Context(), runtimeProvider, req), true
}

func (h *ForwardProxyHandler) evaluatePolicy(req *http.Request, metadata RequestMetadata, route RouteDecision) PolicyDecision {
	if h.PolicyEvaluator == nil {
		return PolicyDecision{Action: "allow"}
	}
	return h.PolicyEvaluator.Evaluate(req, metadata, route)
}

func (h *ForwardProxyHandler) applyDeny(rw http.ResponseWriter, policyDecision PolicyDecision) bool {
	if policyDecision.Action != "deny" {
		return false
	}
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(rw).Encode(map[string]any{
		"error": map[string]string{
			"code":     valueOrDefault(policyDecision.DenyCode, "policy_denied"),
			"message":  valueOrDefault(policyDecision.DenyMessage, "request denied by policy"),
			"policy":   policyDecision.PolicyName,
			"category": valueOrDefault(policyDecision.DenyCategory, "other"),
		},
	})
	return true
}

func (h *ForwardProxyHandler) applyRedirect(rw http.ResponseWriter, policyDecision PolicyDecision) bool {
	if policyDecision.Action != "redirect" || strings.TrimSpace(policyDecision.RedirectURL) == "" {
		return false
	}
	rw.Header().Set("Location", policyDecision.RedirectURL)
	rw.WriteHeader(http.StatusFound)
	return true
}

func (h *ForwardProxyHandler) recordPolicyDecision(ctx context.Context, decision PolicyDecision) {
	UpdateMetadata(ctx, func(metadata *RequestMetadata) {
		metadata.Policy = decision.PolicyName
		metadata.PolicyAction = valueOrDefault(decision.Action, "allow")
		metadata.PolicyReason = valueOrDefault(decision.DenyCode, "none")
		metadata.PolicyCategory = valueOrDefault(decision.DenyCategory, "none")
		metadata.PolicyTrace = append([]string(nil), decision.Trace...)
	})
}

func applyRewrite(req *http.Request, decision PolicyDecision) {
	if req == nil || req.URL == nil {
		return
	}
	if decision.RewriteScheme != "" {
		req.URL.Scheme = decision.RewriteScheme
	}
	if decision.RewriteHost != "" {
		req.URL.Host = decision.RewriteHost
	}
	if decision.RewritePathPrefix != "" {
		path := strings.TrimPrefix(req.URL.Path, "/")
		prefix := strings.TrimSuffix(decision.RewritePathPrefix, "/")
		req.URL.Path = prefix + "/" + path
	}
}

func providerFromContext(ctx context.Context) string {
	metadata, _ := MetadataFromContext(ctx)
	if metadata.Provider == "" {
		return "unknown"
	}
	return metadata.Provider
}

func (h *ForwardProxyHandler) classifyTimeout(err error) TimeoutClassification {
	if h.ClassifyTimeoutFn == nil {
		return TimeoutClassification("unknown")
	}
	return h.ClassifyTimeoutFn(err)
}

func tunnel(clientConn net.Conn, targetConn net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, clientConn)
		closeWrite(targetConn)
	}()

	go func() {
		defer wg.Done()
		_, _ = io.Copy(clientConn, targetConn)
		closeWrite(clientConn)
	}()

	wg.Wait()
	_ = clientConn.Close()
	_ = targetConn.Close()
}

func closeWrite(conn net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if cw, ok := conn.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

func canonicalAddress(hostport string) (string, error) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return "", errors.New("missing CONNECT target")
	}

	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport, nil
	}

	if strings.Contains(hostport, ":") {
		if strings.Count(hostport, ":") > 1 && !strings.HasPrefix(hostport, "[") {
			return net.JoinHostPort(hostport, "443"), nil
		}
		_, _, err := net.SplitHostPort(hostport)
		if err == nil {
			return hostport, nil
		}
	}

	return net.JoinHostPort(hostport, "443"), nil
}

func copyHeader(dst, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

func removeHopHeaders(headers http.Header) {
	connectionTokens := make(map[string]struct{})
	for _, connectionField := range headers.Values("Connection") {
		for _, token := range strings.Split(connectionField, ",") {
			trimmedToken := strings.TrimSpace(token)
			if trimmedToken == "" {
				continue
			}
			connectionTokens[trimmedToken] = struct{}{}
		}
	}

	for token := range connectionTokens {
		headers.Del(token)
	}

	for header := range hopHeaders {
		headers.Del(header)
	}
}

func patchHeaders(headers http.Header, patch map[string]string) {
	for key, value := range patch {
		headers.Set(key, value)
	}
}

func (h *ForwardProxyHandler) CloseIdleConnections() {
	h.Transport.CloseIdleConnections()
}

func (h *ForwardProxyHandler) Shutdown(_ context.Context) error {
	h.Transport.CloseIdleConnections()
	return nil
}

func wrapEndpointError(endpoint *url.URL, err error, class TimeoutClassification) error {
	if endpoint == nil {
		return fmt.Errorf("endpoint <direct> failed (%s): %w", class, err)
	}
	return fmt.Errorf("endpoint %s failed (%s): %w", endpoint, class, err)
}

func timeoutForAttempt(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = 10 * time.Second
	}
	return base + time.Duration(attempt)*250*time.Millisecond
}

func valueOrDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

var _ http.Handler = (*ForwardProxyHandler)(nil)

type defaultDirectAdapter struct{}

func (defaultDirectAdapter) PrepareRequest(req *http.Request, _ *url.URL) (*http.Request, error) {
	return req.Clone(req.Context()), nil
}

func (defaultDirectAdapter) DialConnect(ctx context.Context, targetAddr string, _ *url.URL, dialer *net.Dialer) (net.Conn, error) {
	return dialer.DialContext(ctx, "tcp", targetAddr)
}

func (defaultDirectAdapter) RoundTrip(req *http.Request, _ *url.URL, transport *http.Transport, responseHeaderTimeout time.Duration) (*http.Response, error) {
	cloned := transport.Clone()
	cloned.ResponseHeaderTimeout = responseHeaderTimeout
	return cloned.RoundTrip(req)
}

func (defaultDirectAdapter) RotateIdentity(context.Context) error {
	return ErrRotateIdentityUnsupported
}

func (defaultDirectAdapter) Capabilities() []string { return []string{"forward", "connect"} }

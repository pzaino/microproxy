package listeners

import (
	"context"
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

// ForwardProxyHandler implements HTTP forward proxying and CONNECT tunneling.
type ForwardProxyHandler struct {
	Transport *http.Transport
	Dialer    *net.Dialer

	Resolver          RouteResolver
	Registry          ProviderRegistry
	Selector          EndpointSelector
	ClassifyTimeoutFn TimeoutClassifier
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
	return handler
}

// RequestRuntime bundles runtime routing components.
type RequestRuntime struct {
	Resolver          RouteResolver
	Registry          ProviderRegistry
	Selector          EndpointSelector
	ClassifyTimeoutFn TimeoutClassifier
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
	if resolved {
		UpdateMetadata(req.Context(), func(metadata *RequestMetadata) {
			if decision.TenantID != "" {
				metadata.TenantID = decision.TenantID
			}
			metadata.Provider = decision.Provider
		})
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

	resp, err := h.roundTripWithFallback(outReq, endpoints)
	if err != nil {
		http.Error(rw, fmt.Sprintf("proxy request failed: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	removeHopHeaders(resp.Header)
	copyHeader(rw.Header(), resp.Header)
	rw.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(rw, resp.Body)
}

func (h *ForwardProxyHandler) roundTripWithFallback(req *http.Request, endpoints []RuntimeEndpoint) (*http.Response, error) {
	if len(endpoints) == 0 {
		return h.Transport.RoundTrip(req)
	}

	var errs []error
	for i, endpoint := range endpoints {
		transport := h.Transport.Clone()
		ep := endpoint.URL
		transport.Proxy = http.ProxyURL(ep)
		transport.ResponseHeaderTimeout = timeoutForAttempt(h.Dialer.Timeout, i)

		resp, err := transport.RoundTrip(req)
		if err == nil {
			return resp, nil
		}
		class := h.classifyTimeout(err)
		errs = append(errs, wrapEndpointError(ep, err, class))
		slog.Warn("forward upstream endpoint failed", "provider", providerFromContext(req.Context()), "endpoint", ep.String(), "classification", class, "error", err)
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
	if resolved {
		UpdateMetadata(req.Context(), func(metadata *RequestMetadata) {
			if decision.TenantID != "" {
				metadata.TenantID = decision.TenantID
			}
			metadata.Provider = decision.Provider
		})
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
		conn, err := h.Dialer.DialContext(ctx, "tcp", endpoint.URL.Host)
		if err != nil {
			class := h.classifyTimeout(err)
			errs = append(errs, wrapEndpointError(endpoint.URL, err, class))
			continue
		}

		if err := writeConnect(conn, targetAddr); err != nil {
			_ = conn.Close()
			class := h.classifyTimeout(err)
			errs = append(errs, wrapEndpointError(endpoint.URL, err, class))
			continue
		}

		ok, err := readConnectResponse(conn)
		if err != nil || !ok {
			_ = conn.Close()
			if err == nil {
				err = errors.New("upstream rejected CONNECT")
			}
			class := h.classifyTimeout(err)
			errs = append(errs, wrapEndpointError(endpoint.URL, err, class))
			continue
		}

		return conn, nil
	}
	return nil, errors.Join(errs...)
}

func writeConnect(conn net.Conn, targetAddr string) error {
	_, err := io.WriteString(conn, fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr))
	return err
}

func readConnectResponse(conn net.Conn) (bool, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return false, err
	}
	line := strings.SplitN(string(buffer[:n]), "\r\n", 2)[0]
	return strings.Contains(line, " 200 "), nil
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

func (h *ForwardProxyHandler) CloseIdleConnections() {
	h.Transport.CloseIdleConnections()
}

func (h *ForwardProxyHandler) Shutdown(_ context.Context) error {
	h.Transport.CloseIdleConnections()
	return nil
}

func wrapEndpointError(endpoint *url.URL, err error, class TimeoutClassification) error {
	return fmt.Errorf("endpoint %s failed (%s): %w", endpoint, class, err)
}

func timeoutForAttempt(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = 10 * time.Second
	}
	return base + time.Duration(attempt)*250*time.Millisecond
}

var _ http.Handler = (*ForwardProxyHandler)(nil)

package listeners

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

// ForwardProxyHandler implements HTTP forward proxying and CONNECT tunneling.
type ForwardProxyHandler struct {
	Transport *http.Transport
	Dialer    *net.Dialer
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

func (h *ForwardProxyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodConnect {
		h.handleConnect(rw, req)
		return
	}

	h.handleForward(rw, req)
}

func (h *ForwardProxyHandler) handleForward(rw http.ResponseWriter, req *http.Request) {
	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	if outReq.URL.Scheme == "" {
		outReq.URL.Scheme = "http"
	}
	if outReq.URL.Host == "" {
		outReq.URL.Host = req.Host
	}
	removeHopHeaders(outReq.Header)

	resp, err := h.Transport.RoundTrip(outReq)
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

func (h *ForwardProxyHandler) handleConnect(rw http.ResponseWriter, req *http.Request) {
	targetAddr, err := canonicalAddress(req.Host)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}

	targetConn, err := h.Dialer.DialContext(req.Context(), "tcp", targetAddr)
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

var _ http.Handler = (*ForwardProxyHandler)(nil)

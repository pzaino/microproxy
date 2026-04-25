package dataplane

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/internal/observability"
	"github.com/pzaino/microproxy/pkg/config"
)

func TestForwardProxy_DirectAdapterBearerAuth(t *testing.T) {
	t.Parallel()

	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if got := req.Header.Get("Authorization"); got != "Bearer direct-token" {
			rw.WriteHeader(http.StatusUnauthorized)
			_, _ = rw.Write([]byte("missing direct auth"))
			return
		}
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok-direct"))
	}))
	defer target.Close()

	cfg := &config.Config{
		Providers: []config.ProviderConfig{{
			Name:      "provider-direct",
			Type:      "direct",
			Auth:      config.ProviderAuthConfig{Type: "bearer", Token: "direct-token"},
			Endpoints: []config.ProviderEndpoint{{URL: "http://direct.local", Priority: 1}},
		}},
		Routing: config.RoutingConfig{DefaultProvider: "provider-direct"},
	}

	proxy := startRuntimeProxy(t, cfg)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(target.URL)
	if err != nil {
		t.Fatalf("direct adapter request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", resp.StatusCode, string(body))
	}
	if strings.TrimSpace(string(body)) != "ok-direct" {
		t.Fatalf("unexpected direct response body %q", string(body))
	}
}

func TestForwardProxy_HTTPProxyAdapterBasicAuth_ForwardAndConnect(t *testing.T) {
	t.Parallel()

	targetHTTP := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok-http-proxy"))
	}))
	defer targetHTTP.Close()

	targetTCP := startPingPongTCPServer(t)
	defer targetTCP.Close()

	expectedAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("up-user:up-pass"))
	var sawProxyAuth atomic.Bool
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Header.Get("Proxy-Authorization") == expectedAuth {
			sawProxyAuth.Store(true)
		}

		if req.Method == http.MethodConnect {
			handleConnectRelay(rw, req)
			return
		}

		rsp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
		defer rsp.Body.Close()
		rw.WriteHeader(rsp.StatusCode)
		_, _ = io.Copy(rw, rsp.Body)
	}))
	defer upstream.Close()

	cfg := &config.Config{
		Providers: []config.ProviderConfig{{
			Name:      "provider-http-proxy",
			Type:      "http_proxy",
			Auth:      config.ProviderAuthConfig{Type: "basic", Username: "up-user", Password: "up-pass"},
			Endpoints: []config.ProviderEndpoint{{URL: upstream.URL, Priority: 1}},
		}},
		Routing: config.RoutingConfig{DefaultProvider: "provider-http-proxy"},
	}

	proxy := startRuntimeProxy(t, cfg)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(targetHTTP.URL)
	if err != nil {
		t.Fatalf("http proxy forward request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for forward, got %d", resp.StatusCode)
	}

	if err := assertConnectPingPong(proxy.URL, targetTCP.Addr().String()); err != nil {
		t.Fatalf("http proxy connect failed: %v", err)
	}
	if !sawProxyAuth.Load() {
		t.Fatalf("expected upstream to receive proxy authorization header")
	}
}

func TestForwardProxy_SOCKS5AdapterBasicAuth_ForwardAndConnect(t *testing.T) {
	t.Parallel()

	targetHTTP := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok-socks"))
	}))
	defer targetHTTP.Close()

	targetTCP := startPingPongTCPServer(t)
	defer targetTCP.Close()

	socksListener := startSOCKS5Proxy(t, "sock-user", "sock-pass")
	defer socksListener.Close()

	cfg := &config.Config{
		Providers: []config.ProviderConfig{{
			Name:      "provider-socks",
			Type:      "socks5_proxy",
			Auth:      config.ProviderAuthConfig{Type: "basic", Username: "sock-user", Password: "sock-pass"},
			Endpoints: []config.ProviderEndpoint{{URL: "socks5://" + socksListener.Addr().String(), Priority: 1}},
		}},
		Routing: config.RoutingConfig{DefaultProvider: "provider-socks"},
	}

	proxy := startRuntimeProxy(t, cfg)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := client.Get(targetHTTP.URL)
	if err != nil {
		t.Fatalf("socks forward request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for socks forward, got %d", resp.StatusCode)
	}

	if err := assertConnectPingPong(proxy.URL, targetTCP.Addr().String()); err != nil {
		t.Fatalf("socks connect failed: %v", err)
	}
}

func TestClassifyTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	if got := ClassifyTimeout(ctx.Err()); string(got) != string(TimeoutDeadline) {
		t.Fatalf("expected %q, got %q", TimeoutDeadline, got)
	}
}

func TestForwardProxy_PolicyDenyBlocksRequest(t *testing.T) {
	t.Parallel()

	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("should-not-reach"))
	}))
	defer target.Close()

	cfg := &config.Config{
		Providers: []config.ProviderConfig{{Name: "provider-a", Type: "direct", Endpoints: []config.ProviderEndpoint{{URL: "http://provider.local"}}}},
		Routing: config.RoutingConfig{
			DefaultProvider: "provider-a",
			Rules:           []config.RoutingRule{{Name: "tenant-rule", Match: map[string]string{"tenant": "tenant-a"}, Provider: "provider-a", PolicyRef: "deny-admin"}},
		},
		Policies: []config.PolicyConfig{{
			Name:      "deny-admin",
			Action:    "deny",
			Selectors: map[string]string{"method": "GET", "path_prefix": "/admin"},
			Parameters: map[string]string{
				"reason_code": "admin_blocked",
				"reason":      "admin path denied",
			},
		}},
	}

	proxy := startRuntimeProxy(t, cfg)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/admin", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("policy deny request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", resp.StatusCode)
	}
	var denied map[string]map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&denied); err != nil {
		t.Fatalf("decode deny response: %v", err)
	}
	if denied["error"]["code"] != "admin_blocked" {
		t.Fatalf("unexpected deny payload %+v", denied)
	}
}

func TestForwardProxy_PolicyHeadersPatchAllowsFlow(t *testing.T) {
	t.Parallel()

	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if got := req.Header.Get("X-Policy-Injected"); got != "true" {
			rw.WriteHeader(http.StatusBadRequest)
			_, _ = rw.Write([]byte("missing patched header"))
			return
		}
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok-policy"))
	}))
	defer target.Close()

	cfg := &config.Config{
		Providers: []config.ProviderConfig{{Name: "provider-a", Type: "direct", Endpoints: []config.ProviderEndpoint{{URL: "http://provider.local"}}}},
		Routing: config.RoutingConfig{
			DefaultProvider: "provider-a",
			Rules:           []config.RoutingRule{{Name: "tenant-rule", Match: map[string]string{"tenant": "tenant-a"}, Provider: "provider-a", PolicyRef: "patch-policy"}},
		},
		Policies: []config.PolicyConfig{{Name: "patch-policy", Action: "headers_patch", Parameters: map[string]string{"X-Policy-Injected": "true", "Authorization": "forbidden"}}},
	}

	proxy := startRuntimeProxy(t, cfg)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	req, _ := http.NewRequest(http.MethodGet, target.URL+"/resource", nil)
	req.Header.Set("X-Tenant-ID", "tenant-a")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("policy patch request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
}

func startRuntimeProxy(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()
	handler := listeners.MetadataMiddleware(observability.HTTPMiddleware(listeners.NewForwardProxyHandlerWithRuntime(NewRequestRuntime(cfg)), false))
	return httptest.NewServer(handler)
}

func startPingPongTCPServer(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target tcp: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4)
				if _, err := io.ReadFull(c, buf); err == nil && string(buf) == "ping" {
					_, _ = c.Write([]byte("pong"))
				}
			}(conn)
		}
	}()
	return l
}

func assertConnectPingPong(proxyURL, targetAddr string) error {
	proxyAddr := strings.TrimPrefix(proxyURL, "http://")
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()

	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr); err != nil {
		return err
	}
	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(statusLine, "200") {
		return fmt.Errorf("unexpected status line %q", statusLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		return err
	}
	pong := make([]byte, 4)
	if _, err := io.ReadFull(reader, pong); err != nil {
		return err
	}
	if string(pong) != "pong" {
		return fmt.Errorf("unexpected tunneled response %q", string(pong))
	}
	return nil
}

func handleConnectRelay(rw http.ResponseWriter, req *http.Request) {
	targetConn, err := net.Dial("tcp", req.Host)
	if err != nil {
		rw.WriteHeader(http.StatusBadGateway)
		return
	}

	hj, ok := rw.(http.Hijacker)
	if !ok {
		targetConn.Close()
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		targetConn.Close()
		return
	}
	_, _ = clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	go io.Copy(targetConn, clientConn)
	go io.Copy(clientConn, targetConn)
}

func startSOCKS5Proxy(t *testing.T, expectedUser, expectedPass string) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if err := serveSOCKS5Conn(c, expectedUser, expectedPass); err != nil {
					return
				}
			}(conn)
		}
	}()
	return listener
}

func serveSOCKS5Conn(conn net.Conn, expectedUser, expectedPass string) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
		return err
	}
	authHdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, authHdr); err != nil {
		return err
	}
	user := make([]byte, int(authHdr[1]))
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	pass := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}
	if string(user) != expectedUser || string(pass) != expectedPass {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("invalid socks credentials")
	}
	if _, err := conn.Write([]byte{0x01, 0x00}); err != nil {
		return err
	}

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return err
	}
	if req[1] != 0x01 {
		return fmt.Errorf("unsupported socks cmd %d", req[1])
	}

	host, err := readSOCKS5Addr(conn, req[3])
	if err != nil {
		return err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return err
	}
	port := int(portBytes[0])<<8 | int(portBytes[1])
	targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	target, err := net.Dial("tcp", targetAddr)
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return err
	}
	defer target.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	go io.Copy(target, conn)
	_, _ = io.Copy(conn, target)
	return nil
}

func readSOCKS5Addr(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", err
		}
		buf := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", fmt.Errorf("unsupported atyp %d", atyp)
	}
}

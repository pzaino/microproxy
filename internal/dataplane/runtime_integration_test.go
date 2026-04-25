package dataplane

import (
	"bufio"
	"context"
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

func TestForwardProxy_EndpointFailover(t *testing.T) {
	t.Parallel()

	target := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("ok-from-target"))
	}))
	defer target.Close()

	var firstAttempts atomic.Int32
	upstreamA := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		firstAttempts.Add(1)
		hj, ok := rw.(http.Hijacker)
		if !ok {
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
		conn, _, err := hj.Hijack()
		if err == nil {
			_ = conn.Close()
			return
		}
		rw.WriteHeader(http.StatusBadGateway)
		_ = req.Body.Close()
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rsp, err := http.DefaultTransport.RoundTrip(req)
		if err != nil {
			rw.WriteHeader(http.StatusBadGateway)
			return
		}
		defer rsp.Body.Close()
		rw.Header().Set("X-Upstream", "b")
		rw.WriteHeader(rsp.StatusCode)
		_, _ = io.Copy(rw, rsp.Body)
	}))
	defer upstreamB.Close()

	cfg := &config.Config{
		Providers: []config.ProviderConfig{{
			Name:      "provider-a",
			Endpoints: []config.ProviderEndpoint{{URL: upstreamA.URL, Priority: 1}, {URL: upstreamB.URL, Priority: 2}},
		}},
		Routing: config.RoutingConfig{DefaultProvider: "provider-a"},
	}

	handler := listeners.MetadataMiddleware(observability.HTTPMiddleware(listeners.NewForwardProxyHandlerWithRuntime(NewRequestRuntime(cfg)), false))
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy url: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	req, err := http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Tenant-ID", "tenant-a")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("proxy forward request failed: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", resp.StatusCode, string(body))
	}
	if strings.TrimSpace(string(body)) != "ok-from-target" {
		t.Fatalf("unexpected response body %q", string(body))
	}
	if firstAttempts.Load() == 0 {
		t.Fatalf("expected first upstream to be attempted")
	}
}

func TestConnectProxy_EndpointFailover(t *testing.T) {
	t.Parallel()

	targetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	defer targetListener.Close()

	go func() {
		for {
			conn, err := targetListener.Accept()
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

	upstreamA := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusBadGateway)
	}))
	defer upstreamA.Close()

	upstreamB := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodConnect {
			rw.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
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
	}))
	defer upstreamB.Close()

	cfg := &config.Config{
		Providers: []config.ProviderConfig{{
			Name:      "provider-a",
			Endpoints: []config.ProviderEndpoint{{URL: upstreamA.URL, Priority: 1}, {URL: upstreamB.URL, Priority: 2}},
		}},
		Routing: config.RoutingConfig{DefaultProvider: "provider-a"},
	}

	handler := listeners.MetadataMiddleware(observability.HTTPMiddleware(listeners.NewForwardProxyHandlerWithRuntime(NewRequestRuntime(cfg)), false))
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyAddr := strings.TrimPrefix(proxy.URL, "http://")
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	targetAddr := targetListener.Addr().String()
	_, err = fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nX-Tenant-ID: tenant-a\r\n\r\n", targetAddr, targetAddr)
	if err != nil {
		t.Fatalf("write connect request: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	if !strings.Contains(statusLine, "200") {
		t.Fatalf("expected 200 CONNECT response, got %q", statusLine)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read connect headers: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}

	_, err = conn.Write([]byte("ping"))
	if err != nil {
		t.Fatalf("write tunneled payload: %v", err)
	}
	pong := make([]byte, 4)
	if _, err := io.ReadFull(reader, pong); err != nil {
		t.Fatalf("read tunneled response: %v", err)
	}
	if string(pong) != "pong" {
		t.Fatalf("expected pong, got %q", string(pong))
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

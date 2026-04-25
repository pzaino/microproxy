package dataplane

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/pzaino/microproxy/pkg/config"
)

func TestSOCKS5ListenerManager_ForwardingEndToEnd(t *testing.T) {
	t.Parallel()

	ipv4Target := startPingPongTCPServer(t)
	defer ipv4Target.Close()

	cfg := &config.Config{
		Listeners: []config.ListenerConfig{{
			Name:     "socks",
			Type:     "socks5",
			Address:  "127.0.0.1:0",
			Enabled:  true,
			AuthType: "basic",
			Username: "listener-user",
			Password: "listener-pass",
		}},
		Providers: []config.ProviderConfig{{
			Name:      "direct",
			Type:      "direct",
			Endpoints: []config.ProviderEndpoint{{URL: "http://direct.local", Priority: 1}},
		}},
		Routing: config.RoutingConfig{DefaultProvider: "direct"},
	}

	mgr := NewSOCKS5ListenerManager(cfg.Listeners, time.Second, NewRequestRuntime(cfg))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("start socks5 manager: %v", err)
	}
	defer func() {
		_ = mgr.Shutdown(context.Background())
	}()

	proxyAddr := mgr.servers[0].listener.Addr().String()

	t.Run("ipv4", func(t *testing.T) {
		host, port := splitAddr(t, ipv4Target.Addr().String())
		assertSOCKS5PingPong(t, proxyAddr, host, port, "listener-user", "listener-pass")
	})

	t.Run("domain", func(t *testing.T) {
		_, port := splitAddr(t, ipv4Target.Addr().String())
		assertSOCKS5PingPong(t, proxyAddr, "localhost", port, "listener-user", "listener-pass")
	})

	t.Run("ipv6", func(t *testing.T) {
		ipv6Target, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("ipv6 unavailable: %v", err)
		}
		defer ipv6Target.Close()
		go acceptPingPong(t, ipv6Target)

		host, port := splitAddr(t, ipv6Target.Addr().String())
		assertSOCKS5PingPong(t, proxyAddr, host, port, "listener-user", "listener-pass")
	})
}

func TestSOCKS5ListenerManager_ShutdownClosesActiveConnections(t *testing.T) {
	t.Parallel()

	target := startPingPongTCPServer(t)
	defer target.Close()

	cfg := &config.Config{Listeners: []config.ListenerConfig{{Name: "socks", Type: "socks5", Address: "127.0.0.1:0", Enabled: true}}}
	mgr := NewSOCKS5ListenerManager(cfg.Listeners, time.Second, NewRequestRuntime(cfg))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := mgr.Start(ctx); err != nil {
		t.Fatalf("start socks5 manager: %v", err)
	}

	proxyAddr := mgr.servers[0].listener.Addr().String()
	host, port := splitAddr(t, target.Addr().String())
	conn := dialSOCKS5Tunnel(t, proxyAddr, host, port, "", "")

	shutdownDone := make(chan error, 1)
	go func() {
		shutdownDone <- mgr.Shutdown(context.Background())
	}()

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("expected active SOCKS tunnel to close on shutdown")
	}
	_ = conn.Close()

	if err := <-shutdownDone; err != nil {
		t.Fatalf("shutdown failed: %v", err)
	}

	if conn, err := net.DialTimeout("tcp", proxyAddr, 300*time.Millisecond); err == nil {
		_ = conn.Close()
		t.Fatalf("expected listener to stop accepting connections")
	}
}

func assertSOCKS5PingPong(t *testing.T, proxyAddr, host string, port int, user, pass string) {
	t.Helper()
	conn := dialSOCKS5Tunnel(t, proxyAddr, host, port, user, pass)
	defer conn.Close()

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write ping: %v", err)
	}
	pong := make([]byte, 4)
	if _, err := io.ReadFull(conn, pong); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if string(pong) != "pong" {
		t.Fatalf("unexpected tunnel response %q", string(pong))
	}
}

func dialSOCKS5Tunnel(t *testing.T, proxyAddr, host string, port int, user, pass string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, time.Second)
	if err != nil {
		t.Fatalf("dial socks listener: %v", err)
	}

	method := byte(0x00)
	if user != "" || pass != "" {
		method = 0x02
	}
	if _, err := conn.Write([]byte{0x05, 0x01, method}); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	selected := make([]byte, 2)
	if _, err := io.ReadFull(conn, selected); err != nil {
		t.Fatalf("read method select: %v", err)
	}
	if selected[1] != method {
		t.Fatalf("unexpected auth method %d", selected[1])
	}

	if method == 0x02 {
		authReq := []byte{0x01, byte(len(user))}
		authReq = append(authReq, []byte(user)...)
		authReq = append(authReq, byte(len(pass)))
		authReq = append(authReq, []byte(pass)...)
		if _, err := conn.Write(authReq); err != nil {
			t.Fatalf("write auth request: %v", err)
		}
		authResp := make([]byte, 2)
		if _, err := io.ReadFull(conn, authResp); err != nil {
			t.Fatalf("read auth response: %v", err)
		}
		if authResp[1] != 0x00 {
			t.Fatalf("auth failed with status %d", authResp[1])
		}
	}

	atyp, addrBytes := encodeSOCKS5Addr(t, host)
	connectReq := []byte{0x05, 0x01, 0x00, atyp}
	connectReq = append(connectReq, addrBytes...)
	connectReq = append(connectReq, byte(port>>8), byte(port))
	if _, err := conn.Write(connectReq); err != nil {
		t.Fatalf("write connect request: %v", err)
	}
	replyHead := make([]byte, 4)
	if _, err := io.ReadFull(conn, replyHead); err != nil {
		t.Fatalf("read connect reply header: %v", err)
	}
	if replyHead[1] != 0x00 {
		t.Fatalf("unexpected connect reply %d", replyHead[1])
	}
	if err := consumeSOCKS5AddrPort(conn, replyHead[3]); err != nil {
		t.Fatalf("read connect reply addr: %v", err)
	}
	return conn
}

func encodeSOCKS5Addr(t *testing.T, host string) (byte, []byte) {
	t.Helper()
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return 0x01, v4
		}
		return 0x04, ip.To16()
	}
	if len(host) > 255 {
		t.Fatalf("domain too long: %d", len(host))
	}
	return 0x03, append([]byte{byte(len(host))}, []byte(host)...)
}

func consumeSOCKS5AddrPort(conn net.Conn, atyp byte) error {
	switch atyp {
	case 0x01:
		_, err := io.ReadFull(conn, make([]byte, 4))
		if err != nil {
			return err
		}
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		_, err := io.ReadFull(conn, make([]byte, int(length[0])))
		if err != nil {
			return err
		}
	case 0x04:
		_, err := io.ReadFull(conn, make([]byte, 16))
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported atyp %d", atyp)
	}
	_, err := io.ReadFull(conn, make([]byte, 2))
	return err
}

func splitAddr(t *testing.T, addr string) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host/port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}
	return host, port
}

func acceptPingPong(t *testing.T, listener net.Listener) {
	t.Helper()
	for {
		conn, err := listener.Accept()
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
}

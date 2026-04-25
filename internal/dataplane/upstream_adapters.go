package dataplane

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

type upstreamAdapterFactory struct{}

func (upstreamAdapterFactory) ForProvider(provider config.ProviderConfig) listeners.UpstreamAdapter {
	t := strings.ToLower(strings.TrimSpace(provider.Type))
	switch t {
	case "direct":
		return directAdapter{auth: provider.Auth}
	case "socks5_proxy":
		return socks5ProxyAdapter{auth: provider.Auth}
	case "http_proxy", "https_proxy", "legacy_upstream_proxy":
		return httpProxyAdapter{auth: provider.Auth}
	default:
		for _, capability := range provider.Capabilities {
			switch strings.ToLower(strings.TrimSpace(capability)) {
			case "direct":
				return directAdapter{auth: provider.Auth}
			case "socks5_proxy":
				return socks5ProxyAdapter{auth: provider.Auth}
			case "forward_proxy":
				return httpProxyAdapter{auth: provider.Auth}
			}
		}
		return httpProxyAdapter{auth: provider.Auth}
	}
}

type directAdapter struct {
	auth config.ProviderAuthConfig
}

func (a directAdapter) PrepareRequest(req *http.Request, _ *url.URL) (*http.Request, error) {
	out := req.Clone(req.Context())
	applyRequestAuth(out.Header, a.auth)
	return out, nil
}

func (a directAdapter) DialConnect(ctx context.Context, targetAddr string, _ *url.URL, dialer *net.Dialer) (net.Conn, error) {
	return dialer.DialContext(ctx, "tcp", targetAddr)
}

func (a directAdapter) RoundTrip(req *http.Request, _ *url.URL, transport *http.Transport, responseHeaderTimeout time.Duration) (*http.Response, error) {
	cloned := transport.Clone()
	cloned.ResponseHeaderTimeout = responseHeaderTimeout
	return cloned.RoundTrip(req)
}

func (a directAdapter) RotateIdentity(context.Context) error {
	return listeners.ErrRotateIdentityUnsupported
}
func (a directAdapter) Capabilities() []string { return []string{"forward", "connect"} }

type httpProxyAdapter struct {
	auth config.ProviderAuthConfig
}

func (a httpProxyAdapter) PrepareRequest(req *http.Request, _ *url.URL) (*http.Request, error) {
	out := req.Clone(req.Context())
	applyProxyAuth(out.Header, a.auth)
	return out, nil
}

func (a httpProxyAdapter) DialConnect(ctx context.Context, targetAddr string, endpoint *url.URL, dialer *net.Dialer) (net.Conn, error) {
	if endpoint == nil {
		return nil, errors.New("missing upstream proxy endpoint")
	}

	address := endpoint.Host
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}

	if strings.EqualFold(endpoint.Scheme, "https") {
		serverName := endpoint.Hostname()
		tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn = tlsConn
	}

	connectHeaders := http.Header{}
	applyProxyAuth(connectHeaders, a.auth)
	if err := writeConnect(conn, targetAddr, connectHeaders); err != nil {
		_ = conn.Close()
		return nil, err
	}
	ok, err := readConnectResponse(conn)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if !ok {
		_ = conn.Close()
		return nil, errors.New("upstream rejected CONNECT")
	}
	return conn, nil
}

func (a httpProxyAdapter) RoundTrip(req *http.Request, endpoint *url.URL, transport *http.Transport, responseHeaderTimeout time.Duration) (*http.Response, error) {
	if endpoint == nil {
		return nil, errors.New("missing upstream proxy endpoint")
	}
	cloned := transport.Clone()
	cloned.Proxy = http.ProxyURL(endpoint)
	cloned.ResponseHeaderTimeout = responseHeaderTimeout
	return cloned.RoundTrip(req)
}

func (a httpProxyAdapter) RotateIdentity(context.Context) error {
	return listeners.ErrRotateIdentityUnsupported
}
func (a httpProxyAdapter) Capabilities() []string { return []string{"forward", "connect"} }

type socks5ProxyAdapter struct {
	auth config.ProviderAuthConfig
}

func (a socks5ProxyAdapter) PrepareRequest(req *http.Request, _ *url.URL) (*http.Request, error) {
	return req.Clone(req.Context()), nil
}

func (a socks5ProxyAdapter) DialConnect(ctx context.Context, targetAddr string, endpoint *url.URL, dialer *net.Dialer) (net.Conn, error) {
	conn, err := dialSocks5(ctx, endpoint, targetAddr, dialer, a.auth)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (a socks5ProxyAdapter) RoundTrip(req *http.Request, endpoint *url.URL, transport *http.Transport, responseHeaderTimeout time.Duration) (*http.Response, error) {
	cloned := transport.Clone()
	cloned.Proxy = nil
	cloned.ResponseHeaderTimeout = responseHeaderTimeout
	cloned.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialSocks5(ctx, endpoint, address, &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}, a.auth)
	}
	return cloned.RoundTrip(req)
}

func (a socks5ProxyAdapter) RotateIdentity(context.Context) error {
	return listeners.ErrRotateIdentityUnsupported
}
func (a socks5ProxyAdapter) Capabilities() []string { return []string{"forward", "connect"} }

func applyRequestAuth(headers http.Header, auth config.ProviderAuthConfig) {
	switch strings.ToLower(strings.TrimSpace(auth.Type)) {
	case "bearer":
		if token := strings.TrimSpace(auth.Token); token != "" {
			headers.Set("Authorization", "Bearer "+token)
		}
	case "api_key":
		for key, value := range auth.Headers {
			headers.Set(key, value)
		}
	}
}

func applyProxyAuth(headers http.Header, auth config.ProviderAuthConfig) {
	switch strings.ToLower(strings.TrimSpace(auth.Type)) {
	case "basic":
		credentials := auth.Username + ":" + auth.Password
		headers.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	case "bearer":
		if token := strings.TrimSpace(auth.Token); token != "" {
			headers.Set("Proxy-Authorization", "Bearer "+token)
		}
	case "api_key":
		for key, value := range auth.Headers {
			headers.Set(key, value)
		}
	}
}

func writeConnect(conn net.Conn, targetAddr string, headers http.Header) error {
	builder := strings.Builder{}
	builder.WriteString(fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr))
	for key, values := range headers {
		for _, value := range values {
			builder.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
		}
	}
	builder.WriteString("\r\n")
	_, err := io.WriteString(conn, builder.String())
	return err
}

func readConnectResponse(conn net.Conn) (bool, error) {
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil {
		return false, err
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		if line == "\r\n" {
			break
		}
	}
	return strings.Contains(statusLine, " 200 "), nil
}

func dialSocks5(ctx context.Context, endpoint *url.URL, targetAddr string, dialer *net.Dialer, auth config.ProviderAuthConfig) (net.Conn, error) {
	if endpoint == nil {
		return nil, errors.New("missing socks5 endpoint")
	}
	conn, err := dialer.DialContext(ctx, "tcp", endpoint.Host)
	if err != nil {
		return nil, err
	}
	username := auth.Username
	password := auth.Password
	if strings.EqualFold(auth.Type, "none") || strings.TrimSpace(auth.Type) == "" {
		if endpoint.User != nil {
			username = endpoint.User.Username()
			password, _ = endpoint.User.Password()
		}
	}
	if err := socks5Handshake(conn, username, password, targetAddr); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func socks5Handshake(conn net.Conn, username, password, targetAddr string) error {
	method := byte(0x00)
	if username != "" {
		method = 0x02
	}
	if _, err := conn.Write([]byte{0x05, 0x01, method}); err != nil {
		return err
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return err
	}
	if reply[0] != 0x05 {
		return errors.New("invalid socks version")
	}
	if reply[1] == 0xff {
		return errors.New("socks auth method rejected")
	}
	if reply[1] == 0x02 {
		if len(username) > 255 || len(password) > 255 {
			return errors.New("socks credentials too long")
		}
		payload := []byte{0x01, byte(len(username))}
		payload = append(payload, []byte(username)...)
		payload = append(payload, byte(len(password)))
		payload = append(payload, []byte(password)...)
		if _, err := conn.Write(payload); err != nil {
			return err
		}
		authReply := make([]byte, 2)
		if _, err := io.ReadFull(conn, authReply); err != nil {
			return err
		}
		if authReply[1] != 0x00 {
			return errors.New("socks authentication failed")
		}
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return err
	}
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			req = append(req, 0x01)
			req = append(req, ipv4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return errors.New("socks hostname too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte((port>>8)&0xff), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks connect failed: %d", resp[1])
	}
	var addrLen int
	switch resp[3] {
	case 0x01:
		addrLen = 4
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		addrLen = int(l[0])
	case 0x04:
		addrLen = 16
	default:
		return errors.New("invalid socks bind addr type")
	}
	if addrLen > 0 {
		if _, err := io.ReadFull(conn, make([]byte, addrLen)); err != nil {
			return err
		}
	}
	if _, err := io.ReadFull(conn, make([]byte, 2)); err != nil {
		return err
	}
	return nil
}

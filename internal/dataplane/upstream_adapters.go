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

// ForProvider builds an adapter for a provider with no per-endpoint metadata
// (country/region are blank). It is retained for callers and tests that do not
// have a specific endpoint.
func (upstreamAdapterFactory) ForProvider(provider config.ProviderConfig) listeners.UpstreamAdapter {
	return upstreamAdapterFactory{}.ForProviderEndpoint(provider, config.ProviderEndpoint{})
}

// ForProviderEndpoint builds an adapter for a specific endpoint, closing over that
// endpoint's static country/region metadata so credential templates that source
// from endpoint.country / endpoint.region resolve correctly.
func (upstreamAdapterFactory) ForProviderEndpoint(provider config.ProviderConfig, endpoint config.ProviderEndpoint) listeners.UpstreamAdapter {
	t := strings.ToLower(strings.TrimSpace(provider.Type))
	components := buildAuthComponents(provider)
	endpointMeta := config.EndpointMetadata{
		Country: strings.TrimSpace(endpoint.Country),
		Region:  strings.TrimSpace(endpoint.Region),
	}
	switch t {
	case "direct":
		return directAdapter{auth: provider.Auth}
	case "socks5_proxy":
		return socks5ProxyAdapter{auth: provider.Auth}
	case "http_proxy", "https_proxy", "legacy_upstream_proxy":
		return components.toAdapter(strings.TrimSpace(provider.Name), endpointMeta)
	default:
		for _, capability := range provider.Capabilities {
			switch strings.ToLower(strings.TrimSpace(capability)) {
			case "direct":
				return directAdapter{auth: provider.Auth}
			case "socks5_proxy":
				return socks5ProxyAdapter{auth: provider.Auth}
			case "forward_proxy":
				return components.toAdapter(strings.TrimSpace(provider.Name), endpointMeta)
			}
		}
		return components.toAdapter(strings.TrimSpace(provider.Name), endpointMeta)
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
	providerName   string
	auth           config.ProviderAuthConfig
	renderer       *config.CredentialRenderer
	rendererErr    error  // non-nil when a configured template could not be built
	legacyTemplate string // legacy username_template mode
	sessionMode    string // "username_template" | "credential_template" | ""
	sessionEnabled bool
	endpoint       config.EndpointMetadata
}

// authComponents are the per-provider rendering decisions built once and shared
// by every endpoint of the provider.
type authComponents struct {
	auth           config.ProviderAuthConfig
	renderer       *config.CredentialRenderer
	rendererErr    error
	legacyTemplate string
	sessionMode    string
	sessionEnabled bool
}

func buildAuthComponents(provider config.ProviderConfig) authComponents {
	comp := authComponents{
		auth:           provider.Auth,
		legacyTemplate: provider.Session.UsernameTemplate,
		sessionEnabled: provider.Session.SessionEnabled(),
		sessionMode:    strings.ToLower(strings.TrimSpace(provider.Session.Mode)),
	}
	// Build the generic renderer only when a username/password template is
	// present. A build error is stored so effectiveCredentials fails closed.
	if config.HasCredentialTemplates(provider.Auth) {
		renderer, err := config.NewCredentialRenderer(provider.Auth.Templates, provider.Auth.Parameters)
		comp.renderer = renderer
		comp.rendererErr = err
	}
	return comp
}

func (c authComponents) toAdapter(providerName string, endpoint config.EndpointMetadata) httpProxyAdapter {
	return httpProxyAdapter{
		providerName:   providerName,
		auth:           c.auth,
		renderer:       c.renderer,
		rendererErr:    c.rendererErr,
		legacyTemplate: c.legacyTemplate,
		sessionMode:    c.sessionMode,
		sessionEnabled: c.sessionEnabled,
		endpoint:       endpoint,
	}
}

// pinnedSnapshot returns the pinned sticky-session snapshot for this provider,
// failing closed when it is missing or belongs to another provider. A session
// identity has no silent fallback: a missing or mismatched snapshot is a hard
// error so stickiness is never broken and non-sticky egress is never leaked.
func (a httpProxyAdapter) pinnedSnapshot(ctx context.Context) (listeners.SessionSnapshot, error) {
	snapshot, ok := listeners.SessionSnapshotFromContext(ctx)
	if !ok {
		return listeners.SessionSnapshot{}, fmt.Errorf("provider %q: sticky session snapshot is missing", a.providerName)
	}
	if strings.TrimSpace(snapshot.Provider) != strings.TrimSpace(a.providerName) {
		return listeners.SessionSnapshot{}, fmt.Errorf("provider %q: sticky session snapshot provider %q does not match", a.providerName, snapshot.Provider)
	}
	return snapshot, nil
}

// effectiveCredentials composes the final (username, password) sent to the
// upstream. It supports, independently and additively:
//   - legacy username_template sticky mode (unchanged): render the username from
//     session.username_template with the pinned session id, keep the base password;
//   - generic credential templating (auth.templates + auth.parameters): render
//     username and/or password from base credentials, static/endpoint parameters
//     and, for credential_template mode, the pinned session id;
//   - the legacy endpoint-userinfo fallback for untyped, non-templated auth.
//
// Any required-but-unresolved input fails closed: the credential is never
// silently downgraded to the base value or to direct egress.
func (a httpProxyAdapter) effectiveCredentials(ctx context.Context, endpoint *url.URL) (string, string, error) {
	// A configured but unbuildable template must fail closed before any dial.
	if a.rendererErr != nil {
		return "", "", fmt.Errorf("provider %q: invalid credential template: %w", a.providerName, a.rendererErr)
	}
	username := a.auth.Username
	password := a.auth.Password

	// Legacy username_template sticky mode: unchanged behaviour.
	if a.sessionMode == "username_template" {
		snapshot, err := a.pinnedSnapshot(ctx)
		if err != nil {
			return "", "", err
		}
		rendered, err := a.renderStickyUsername(snapshot.SessionID)
		if err != nil {
			return "", "", err
		}
		username = rendered
	}

	// Generic credential rendering (credential_template mode and static
	// templating share this path).
	if a.renderer != nil {
		sessionID := ""
		if a.sessionMode == "credential_template" {
			snapshot, err := a.pinnedSnapshot(ctx)
			if err != nil {
				return "", "", err
			}
			sessionID = snapshot.SessionID
		}
		renderedUser, renderedPass, err := a.renderer.Render(config.CredentialRenderContext{
			Username:  a.auth.Username,
			Password:  a.auth.Password,
			SessionID: sessionID,
			Endpoint:  a.endpoint,
		})
		if err != nil {
			return "", "", fmt.Errorf("provider %q: render credential template: %w", a.providerName, err)
		}
		username = renderedUser
		password = renderedPass
	}

	// Preserve endpoint-userinfo fallback for non-templated, untyped static auth.
	if a.renderer == nil {
		if strings.TrimSpace(a.auth.Type) == "" || strings.EqualFold(strings.TrimSpace(a.auth.Type), "none") {
			if strings.TrimSpace(username) == "" && endpoint != nil && endpoint.User != nil {
				username = endpoint.User.Username()
				password, _ = endpoint.User.Password()
			}
		}
	}
	return username, password, nil
}

// renderStickyUsername renders a legacy username_template with the pinned
// session id. A sticky template must be well-formed and must embed the session
// id; a template that would not vary per session fails closed so stickiness is
// never silently broken.
func (a httpProxyAdapter) renderStickyUsername(sessionID string) (string, error) {
	if err := config.ValidateUsernameTemplate(a.legacyTemplate); err != nil {
		return "", fmt.Errorf("provider %q: render sticky session username: %w", a.providerName, err)
	}
	rendered, err := config.RenderUsername(a.legacyTemplate, a.auth.Username, sessionID)
	if err != nil {
		return "", fmt.Errorf("provider %q: render sticky session username: %w", a.providerName, err)
	}
	if strings.TrimSpace(rendered) == "" {
		return "", fmt.Errorf("provider %q: rendered sticky session username is empty", a.providerName)
	}
	return rendered, nil
}

// applyRenderedAuth sets basic Proxy-Authorization on headers from the effective
// credentials, overriding the base auth type when the adapter is session-enabled
// so a rendered credential is always delivered as basic.
func (a httpProxyAdapter) applyRenderedAuth(headers http.Header, username, password string, endpoint *url.URL) {
	effective := a.auth
	effective.Username = username
	effective.Password = password
	if a.sessionMode == "credential_template" || a.sessionMode == "username_template" {
		effective.Type = "basic"
	}
	applyProxyAuth(headers, effective, endpoint)
}

func (a httpProxyAdapter) PrepareRequest(req *http.Request, _ *url.URL) (*http.Request, error) {
	out := req.Clone(req.Context())
	username, password, err := a.effectiveCredentials(req.Context(), nil)
	if err != nil {
		return nil, err
	}
	// Session mode and templated credentials are always delivered as basic
	// Proxy-Authorization.
	a.applyRenderedAuth(out.Header, username, password, nil)
	return out, nil
}

func (a httpProxyAdapter) DialConnect(ctx context.Context, targetAddr string, endpoint *url.URL, dialer *net.Dialer) (net.Conn, error) {
	if endpoint == nil {
		return nil, errors.New("missing upstream proxy endpoint")
	}

	// Resolve credentials before dialing so a session failure never contacts
	// the upstream proxy.
	username, password, err := a.effectiveCredentials(ctx, endpoint)
	if err != nil {
		return nil, err
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
	a.applyRenderedAuth(connectHeaders, username, password, endpoint)
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
	return a.transportFor(endpoint, transport, responseHeaderTimeout).RoundTrip(req)
}

// transportFor clones the shared transport for one upstream endpoint. Session
// mode disables keep-alives so a pooled connection authenticated with an old
// identity can never be reused after rotation.
func (a httpProxyAdapter) transportFor(endpoint *url.URL, transport *http.Transport, responseHeaderTimeout time.Duration) *http.Transport {
	cloned := transport.Clone()
	cloned.Proxy = http.ProxyURL(endpoint)
	cloned.ResponseHeaderTimeout = responseHeaderTimeout
	if a.sessionEnabled {
		// Prevent accidental reuse of an old authenticated upstream connection
		// after rotation. Each sticky request gets a fresh TCP connection to
		// the upstream proxy; the per-request Proxy-Authorization header
		// already carries the pinned session identity.
		cloned.DisableKeepAlives = true
		cloned.MaxIdleConnsPerHost = 0
		cloned.IdleConnTimeout = 0
	}
	return cloned
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

func applyProxyAuth(headers http.Header, auth config.ProviderAuthConfig, endpoint *url.URL) {
	authType := strings.ToLower(strings.TrimSpace(auth.Type))
	if authType == "" || authType == "none" {
		if endpoint != nil && endpoint.User != nil {
			authType = "basic"
			auth.Username = endpoint.User.Username()
			auth.Password, _ = endpoint.User.Password()
		}
	}

	switch authType {
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

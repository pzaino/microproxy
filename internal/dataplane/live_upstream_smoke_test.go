package dataplane

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pzaino/microproxy/internal/dataplane/listeners"
	"github.com/pzaino/microproxy/pkg/config"
)

// TestLiveUpstreamStickySmoke is an opt-in live check against a real upstream
// proxy. It is skipped unless MICROPROXY_LIVE_SMOKE=1 and is never suitable for
// ordinary CI. It distinguishes three facts that must not be conflated:
//
//   - identity_changed: the local pinned session credential was replaced;
//   - post_rotation_upstream_connection_succeeded: the new credential was
//     accepted on a new upstream connection;
//   - observed_public_ip_changed: the egress IP observed through an IP echo
//     endpoint differs. This can legitimately be false even when rotation is
//     correct, because the upstream provider decides whether a new sticky
//     identity maps to a new exit IP.
//
// Required environment:
//
//	MICROPROXY_LIVE_SMOKE=1
//	MICROPROXY_LIVE_UPSTREAM_URL=http://upstream.example:3128
//	MICROPROXY_LIVE_UPSTREAM_USER=base-user
//	MICROPROXY_LIVE_UPSTREAM_PASSWORD=base-password
//
// Optional:
//
//	MICROPROXY_LIVE_ECHO_URL=https://api.ipify.org?format=text
//	MICROPROXY_LIVE_SESSION_MODE=username_template|credential_template
//	MICROPROXY_LIVE_USERNAME_TEMPLATE={{username}}-session-{{session_id}}
//	MICROPROXY_LIVE_TEMPLATE_USERNAME={{username}}.{{session_id}}
//	MICROPROXY_LIVE_TEMPLATE_PASSWORD={{password}}-{{session_id}}
//	MICROPROXY_LIVE_SESSION_LENGTH=32
//	MICROPROXY_LIVE_SESSION_CHARSET=hex
//	MICROPROXY_LIVE_TIMEOUT_SECONDS=30
//
// For credential_template mode, set at least one of the two template variables;
// the renderer validates that {{session_id}} is present.
//
// The upstream URL must not embed credentials; use the separate user/password
// variables so test failures and logs never contain userinfo.
func withSessionID(session config.ProviderSessionConfig, id config.SessionIDConfig) config.ProviderSessionConfig {
	session.ID = id
	return session
}

func TestLiveUpstreamStickySmoke(t *testing.T) {
	if os.Getenv("MICROPROXY_LIVE_SMOKE") != "1" {
		t.Skip("live upstream smoke test is opt-in: set MICROPROXY_LIVE_SMOKE=1")
	}

	upstreamURL := strings.TrimSpace(os.Getenv("MICROPROXY_LIVE_UPSTREAM_URL"))
	username := strings.TrimSpace(os.Getenv("MICROPROXY_LIVE_UPSTREAM_USER"))
	password := os.Getenv("MICROPROXY_LIVE_UPSTREAM_PASSWORD")
	if upstreamURL == "" || username == "" || password == "" {
		t.Fatal("MICROPROXY_LIVE_UPSTREAM_URL, MICROPROXY_LIVE_UPSTREAM_USER and MICROPROXY_LIVE_UPSTREAM_PASSWORD are required")
	}
	parsedUpstream, err := url.Parse(upstreamURL)
	if err != nil || parsedUpstream.Scheme == "" || parsedUpstream.Host == "" {
		t.Fatal("MICROPROXY_LIVE_UPSTREAM_URL must be a valid absolute URL")
	}
	if parsedUpstream.User != nil {
		t.Fatal("MICROPROXY_LIVE_UPSTREAM_URL must not embed credentials; use MICROPROXY_LIVE_UPSTREAM_USER/PASSWORD")
	}

	echoURL := strings.TrimSpace(os.Getenv("MICROPROXY_LIVE_ECHO_URL"))
	if echoURL == "" {
		echoURL = "https://api.ipify.org?format=text"
	}
	sessionMode := strings.TrimSpace(os.Getenv("MICROPROXY_LIVE_SESSION_MODE"))
	if sessionMode == "" {
		sessionMode = "username_template"
	}
	auth := config.ProviderAuthConfig{Type: "basic", Username: username, Password: password}
	session := config.ProviderSessionConfig{Supported: true, Mode: sessionMode}
	switch sessionMode {
	case "username_template":
		template := strings.TrimSpace(os.Getenv("MICROPROXY_LIVE_USERNAME_TEMPLATE"))
		if template == "" {
			template = "{{username}}-session-{{session_id}}"
		}
		session.UsernameTemplate = template
	case "credential_template":
		auth.Templates = config.CredentialTemplates{
			Username: strings.TrimSpace(os.Getenv("MICROPROXY_LIVE_TEMPLATE_USERNAME")),
			Password: os.Getenv("MICROPROXY_LIVE_TEMPLATE_PASSWORD"),
		}
		if auth.Templates.Username == "" && strings.TrimSpace(auth.Templates.Password) == "" {
			t.Fatal("credential_template live smoke requires MICROPROXY_LIVE_TEMPLATE_USERNAME and/or MICROPROXY_LIVE_TEMPLATE_PASSWORD")
		}
	default:
		t.Fatalf("MICROPROXY_LIVE_SESSION_MODE must be username_template or credential_template, got %q", sessionMode)
	}
	sessionIDCfg := config.SessionIDConfig{}
	if rawLength := strings.TrimSpace(os.Getenv("MICROPROXY_LIVE_SESSION_LENGTH")); rawLength != "" {
		length, parseErr := strconv.Atoi(rawLength)
		if parseErr != nil || length < config.SessionIDMinLength || length > config.SessionIDMaxLength {
			t.Fatalf("MICROPROXY_LIVE_SESSION_LENGTH must be an integer in [%d,%d]", config.SessionIDMinLength, config.SessionIDMaxLength)
		}
		sessionIDCfg.Length = length
	}
	sessionIDCfg.Charset = strings.TrimSpace(os.Getenv("MICROPROXY_LIVE_SESSION_CHARSET"))

	timeout := 30 * time.Second
	if rawTimeout := strings.TrimSpace(os.Getenv("MICROPROXY_LIVE_TIMEOUT_SECONDS")); rawTimeout != "" {
		seconds, parseErr := strconv.Atoi(rawTimeout)
		if parseErr != nil || seconds <= 0 || seconds > 300 {
			t.Fatal("MICROPROXY_LIVE_TIMEOUT_SECONDS must be an integer in [1,300]")
		}
		timeout = time.Duration(seconds) * time.Second
	}

	const providerName = "live-sticky"
	cfg := &config.Config{
		SchemaVersion: "1",
		Providers: []config.ProviderConfig{
			{
				Name: providerName,
				Type: "http_proxy",
				Auth: auth,
				Endpoints: []config.ProviderEndpoint{
					{URL: upstreamURL},
				},
				Session:      withSessionID(session, sessionIDCfg),
				Health:       config.ProviderHealthConfig{Enabled: false},
				Capabilities: []string{"forward_proxy"},
			},
		},
		SessionControl: config.SessionControlConfig{
			Enabled:     true,
			Address:     "127.0.0.1:0",
			AuthType:    config.SessionControlAuthBearer,
			BearerToken: "live-smoke-session-api-token",
			Provider:    providerName,
		},
	}
	manager, err := NewSessionManager(cfg)
	if err != nil {
		t.Fatalf("init session manager: %v", err)
	}
	runtime := NewRequestRuntimeWithSessionManager(cfg, manager)
	handler := listeners.NewForwardProxyHandlerWithRuntime(runtime)
	proxyServer := httptest.NewServer(listeners.MetadataMiddleware(
		listeners.ListenerBindingMiddleware("live-sticky", providerName, handler),
	))
	defer proxyServer.Close()
	_, apiBase := startSessionAPI(t, cfg, manager)

	fetchObservation := func() (string, error) {
		client := proxyClient(proxyServer.URL)
		client.Timeout = timeout
		resp, err := client.Get(echoURL)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return "", fmt.Errorf("echo endpoint returned status %d", resp.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(body)), nil
	}

	first, firstErr := fetchObservation()
	if firstErr != nil {
		t.Fatalf("pre-rotation upstream observation failed: %v", firstErr)
	}
	second, secondErr := fetchObservation()
	if secondErr != nil {
		t.Fatalf("second pre-rotation upstream observation failed: %v", secondErr)
	}

	before, ok := manager.Snapshot(providerName)
	if !ok {
		t.Fatal("session manager has no pinned identity")
	}
	rotateReq, err := http.NewRequest(http.MethodPost, apiBase+"/api/v1/sessions/rotate", nil)
	if err != nil {
		t.Fatalf("build rotate request: %v", err)
	}
	rotateReq.Header.Set("Authorization", "Bearer live-smoke-session-api-token")
	rotateReq.Header.Set("Idempotency-Key", "live-smoke-"+strconv.FormatInt(time.Now().UnixNano(), 10))
	rotateResp, err := (&http.Client{Timeout: 10 * time.Second}).Do(rotateReq)
	if err != nil {
		t.Fatalf("rotate request failed: %v", err)
	}
	rotateBody, _ := io.ReadAll(io.LimitReader(rotateResp.Body, 4096))
	rotateResp.Body.Close()
	if rotateResp.StatusCode != http.StatusOK {
		// The API error envelope never contains credentials or the session id.
		t.Fatalf("rotate returned %d: %s", rotateResp.StatusCode, strings.TrimSpace(string(rotateBody)))
	}
	after, ok := manager.Snapshot(providerName)
	if !ok {
		t.Fatal("session manager lost its pinned identity after rotation")
	}

	third, thirdErr := fetchObservation()
	identityChanged := before.SessionID != after.SessionID
	connectionSucceeded := thirdErr == nil
	ipChanged := connectionSucceeded && first != "" && third != first
	preRotationStable := first == second

	t.Logf("identity_changed=%t", identityChanged)
	t.Logf("post_rotation_upstream_connection_succeeded=%t", connectionSucceeded)
	t.Logf("observed_public_ip_changed=%t", ipChanged)
	t.Logf("pre_rotation_observation_stable=%t", preRotationStable)

	if !identityChanged {
		t.Fatal("rotation did not change the pinned session identity")
	}
	if !connectionSucceeded {
		t.Fatalf("post-rotation upstream connection failed: %v", thirdErr)
	}

	// Deliberately no retry loop: a provider is allowed to reuse an exit IP for
	// a new session id. The operator decides whether that is acceptable.
}

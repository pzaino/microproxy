package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAuthenticatorRequiresCredentialsOutsideDevelopment(t *testing.T) {
	t.Setenv(controlPlaneAPIKeysEnv, "")
	t.Setenv(controlPlaneJWTsEnv, "")
	t.Setenv(developmentModeEnv, "false")

	_, err := newAuthenticator()
	if err == nil {
		t.Fatalf("expected authenticator configuration error")
	}
}

func TestNewAuthenticatorDevelopmentModeUsesDefaultAPIKey(t *testing.T) {
	t.Setenv(controlPlaneAPIKeysEnv, "")
	t.Setenv(controlPlaneJWTsEnv, "")
	t.Setenv(developmentModeEnv, "true")

	authenticator, err := newAuthenticator()
	if err != nil {
		t.Fatalf("newAuthenticator: %v", err)
	}

	if _, ok := authenticator.apiKeys[defaultControlAPIKey]; !ok {
		t.Fatalf("expected default control-plane api key to be configured")
	}
}

func TestAuthorizeWithoutConfiguredCredentialsReturnsForbidden(t *testing.T) {
	a := requestAuthenticator{apiKeys: map[string]struct{}{}, jwts: map[string]struct{}{}}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/config", nil)
	req.Header.Set(apiKeyHeader, "unknown-key")

	allowed, status, code, _ := a.authorize(req)
	if allowed {
		t.Fatalf("expected unauthorized request to be rejected")
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 got %d", status)
	}
	if code != "forbidden" {
		t.Fatalf("expected forbidden code got %q", code)
	}
}

func TestParseDevelopmentMode(t *testing.T) {
	for _, value := range []string{"1", "true", "TRUE", "yes", "on"} {
		if !parseDevelopmentMode(value) {
			t.Fatalf("expected %q to enable development mode", value)
		}
	}
	for _, value := range []string{"", "0", "false", "no", "off"} {
		if parseDevelopmentMode(value) {
			t.Fatalf("expected %q to disable development mode", value)
		}
	}
}

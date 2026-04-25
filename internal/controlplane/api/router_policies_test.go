package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pzaino/microproxy/pkg/config"
)

func TestPolicyDryRunEndpoint(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Policies = []config.PolicyConfig{{
		Name:   "block-json",
		Type:   "inline",
		Action: "deny",
		Selectors: map[string]string{
			"content_type_regex": "^application/json",
		},
		Parameters: map[string]string{
			"reason_code":   "content_blocked",
			"deny_category": "content",
			"reason":        "json denied",
			"chain_mode":    "stop",
		},
	}}
	h := newTestRouter(t, cfg)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/dry-run", strings.NewReader(`{"policyRef":"block-json","method":"POST","url":"http://example.local/data","headers":{"Content-Type":"application/json"}}`))
	withDefaultAuth(req)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d body=%s", rw.Code, rw.Body.String())
	}

	var response PolicyDryRunResponse
	if err := json.Unmarshal(rw.Body.Bytes(), &response); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if response.Decision.Action != "deny" {
		t.Fatalf("expected deny action, got %+v", response.Decision)
	}
	if response.Decision.DenyCategory != "content" {
		t.Fatalf("expected deny category content, got %q", response.Decision.DenyCategory)
	}
}

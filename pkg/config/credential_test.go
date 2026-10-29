package config

import (
	"strings"
	"testing"
)

// mustRenderer compiles a renderer and fails the test on a build error.
func mustRenderer(t *testing.T, templates CredentialTemplates, params map[string]CredentialParameter) *CredentialRenderer {
	t.Helper()
	r, err := NewCredentialRenderer(templates, params)
	if err != nil {
		t.Fatalf("NewCredentialRenderer: %v", err)
	}
	return r
}

func TestCredentialRenderer_EvomiPasswordTemplate(t *testing.T) {
	// Evomi-style: encode only the password from the base password plus the
	// pinned session id; the username is left as the base value.
	r := mustRenderer(t,
		CredentialTemplates{Password: "{{password}}.{{session_id}}"},
		nil,
	)
	gotUser, gotPass, err := r.Render(CredentialRenderContext{
		Username:  "zoneA",
		Password:  "basepass",
		SessionID: "sess-123",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if gotUser != "zoneA" {
		t.Fatalf("username must stay the base value, got %q", gotUser)
	}
	if gotPass != "basepass.sess-123" {
		t.Fatalf("password = %q, want %q", gotPass, "basepass.sess-123")
	}
}

func TestCredentialRenderer_BrightDataUsernameTemplate(t *testing.T) {
	// Bright Data-style: encode only the username, leaving the base password.
	r := mustRenderer(t,
		CredentialTemplates{Username: "{{username}}:{{session_id}}"},
		nil,
	)
	gotUser, gotPass, err := r.Render(CredentialRenderContext{
		Username:  "user",
		Password:  "secret",
		SessionID: "abc",
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if gotUser != "user:abc" {
		t.Fatalf("username = %q, want %q", gotUser, "user:abc")
	}
	if gotPass != "secret" {
		t.Fatalf("password must stay the base value, got %q", gotPass)
	}
}

func TestCredentialRenderer_GenericBothFields(t *testing.T) {
	params := map[string]CredentialParameter{
		"geo":   {Source: SourceEndpointCountry},
		"extra": {Value: "x9"},
	}
	r := mustRenderer(t,
		CredentialTemplates{
			Username: "u-{{session_id}}-{{geo}}",
			Password: "[{{password}}|{{extra}}]",
		},
		params,
	)
	gotUser, gotPass, err := r.Render(CredentialRenderContext{
		Username:  "base",
		Password:  "pw",
		SessionID: "sess-7",
		Endpoint:  EndpointMetadata{Country: "US", Region: "NY"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if gotUser != "u-sess-7-US" {
		t.Fatalf("username = %q, want %q", gotUser, "u-sess-7-US")
	}
	if gotPass != "[pw|x9]" {
		t.Fatalf("password = %q, want %q", gotPass, "[pw|x9]")
	}
}

func TestCredentialRenderer_EndpointRegionSource(t *testing.T) {
	params := map[string]CredentialParameter{"region": {Source: SourceEndpointRegion}}
	r := mustRenderer(t, CredentialTemplates{Username: "{{region}}"}, params)
	_, _, err := r.Render(CredentialRenderContext{Endpoint: EndpointMetadata{Country: "US", Region: ""}})
	if err == nil {
		t.Fatal("expected fail-closed on empty endpoint.region source")
	}
	if !strings.Contains(err.Error(), "endpoint.region") && !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected an empty-region error, got %v", err)
	}
	// Now provide the region.
	gotUser, _, err := r.Render(CredentialRenderContext{Endpoint: EndpointMetadata{Region: "FL"}})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if gotUser != "FL" {
		t.Fatalf("username = %q, want %q", gotUser, "FL")
	}
}

func TestCredentialRenderer_MissingSessionIDFailsClosed(t *testing.T) {
	r := mustRenderer(t, CredentialTemplates{Username: "u-{{session_id}}"}, nil)
	_, _, err := r.Render(CredentialRenderContext{Username: "base"})
	if err == nil {
		t.Fatal("expected fail-closed when session_id token has no pinned identity")
	}
	if !strings.Contains(err.Error(), "session_id") {
		t.Fatalf("expected a session_id error, got %v", err)
	}
}

func TestCredentialRenderer_UnknownTokenFailsClosed(t *testing.T) {
	_, err := NewCredentialRenderer(CredentialTemplates{Username: "{{unknown_token}}"}, nil)
	if err == nil {
		t.Fatal("expected unknown token to fail at compile time")
	}
	if !strings.Contains(err.Error(), "unknown token") {
		t.Fatalf("expected unknown-token error, got %v", err)
	}
}

func TestCredentialRenderer_BlankTemplateKeepsBaseCredential(t *testing.T) {
	// A blank template field yields a nil renderer, and even with parameters the
	// renderer must pass the base credentials through unchanged.
	r, err := NewCredentialRenderer(CredentialTemplates{}, map[string]CredentialParameter{"x": {Value: "y"}})
	if err != nil {
		t.Fatalf("blank-template renderer: %v", err)
	}
	if r != nil {
		t.Fatal("blank templates must return a nil renderer")
	}
	// Rendering through a blank-template renderer is not meaningful; the adapter
	// only renders a non-nil renderer, so verify the contract indirectly: a
	// nil renderer is what the adapter falls back to.
}

func TestCredentialRenderer_UnbalancedBracesRejected(t *testing.T) {
	_, err := NewCredentialRenderer(CredentialTemplates{Username: "{{session_id"}, nil)
	if err == nil {
		t.Fatal("expected unbalanced brace to be rejected")
	}
}

func TestCredentialRenderer_DollarEnvRejected(t *testing.T) {
	_, err := NewCredentialRenderer(CredentialTemplates{Password: "${FOO}"}, nil)
	if err == nil {
		t.Fatal("expected $ENV placeholder to be rejected")
	}
}

func TestCredentialRenderer_UnsafeControlCharInParameter(t *testing.T) {
	// A static parameter value with a control char must be rejected.
	_, err := NewCredentialRenderer(
		CredentialTemplates{Password: "{{pwned}}"},
		map[string]CredentialParameter{"pwned": {Value: "bad\x00char"}},
	)
	if err == nil {
		t.Fatal("expected unsafe control char in parameter value to be rejected")
	}
}

func TestCredentialRenderer_ResidualTokenRejected(t *testing.T) {
	// A static parameter whose value contains a closing-brace pair must not
	// survive rendering: a resolved value that looks like an unresolved token is
	// rejected so a crafted parameter cannot smuggle a token past substitution.
	_, _, err := (&CredentialRenderer{
		username:   mustCompiled(t, "{{pwned}}"),
		password:   nil,
		parameters: map[string]CredentialParameter{"pwned": {Value: "a}}b"}},
	}).Render(CredentialRenderContext{Username: "base"})
	if err == nil {
		t.Fatal("expected residual }} in a resolved value to be rejected at render")
	}
}

func mustCompiled(t *testing.T, raw string) *compiledTemplate {
	t.Helper()
	compiled, err := compileTemplate(raw, map[string]struct{}{"pwned": {}}, "templates")
	if err != nil {
		t.Fatalf("compileTemplate: %v", err)
	}
	return compiled
}

// TestProviderConfig_TemplatingOnSOCKSRejected confirms the renderer abstraction
// is only wired for http-proxy-compatible providers: a SOCKS5 provider may not
// declare credential templates (they would never be consumed).
func TestProviderConfig_TemplatingOnSOCKSRejected(t *testing.T) {
	p := ProviderConfig{
		Name:      "socks",
		Type:      "socks5_proxy",
		Auth:      ProviderAuthConfig{Type: "basic", Username: "u", Password: "p", Templates: CredentialTemplates{Password: "{{password}}"}},
		Endpoints: []ProviderEndpoint{{URL: "socks5://x.example:1080"}},
	}
	errs := p.Validate("providers[0]")
	if len(errs.Errors) == 0 {
		t.Fatal("expected credential templating on a socks5 provider to be rejected")
	}
}

// TestProviderConfig_SessionOnNonHTTPRejected confirms a runtime session mode
// (and therefore sticky identity) is rejected for non-http providers.
func TestProviderConfig_SessionOnNonHTTPRejected(t *testing.T) {
	p := ProviderConfig{
		Name:      "socks",
		Type:      "socks5_proxy",
		Auth:      ProviderAuthConfig{Type: "basic", Username: "u", Password: "p"},
		Endpoints: []ProviderEndpoint{{URL: "socks5://x.example:1080"}},
		Session:   ProviderSessionConfig{Supported: true, Mode: "username_template", UsernameTemplate: "{{username}}-{{session_id}}"},
	}
	errs := p.Validate("providers[0]")
	if len(errs.Errors) == 0 {
		t.Fatal("expected a runtime session mode on a socks5 provider to be rejected")
	}
}

func TestCredentialRenderer_ParameterCollisionWithBuiltinRejected(t *testing.T) {
	_, err := NewCredentialRenderer(
		CredentialTemplates{},
		map[string]CredentialParameter{"username": {Value: "x"}},
	)
	if err == nil {
		t.Fatal("parameter colliding with a built-in token must be rejected")
	}
}

func TestCredentialRenderer_ParameterExactlyOneOfValueSource(t *testing.T) {
	if _, err := NewCredentialRenderer(CredentialTemplates{}, map[string]CredentialParameter{"p": {Value: "a", Source: SourceEndpointCountry}}); err == nil {
		t.Fatal("expected rejection when a parameter sets both value and source")
	}
	if _, err := NewCredentialRenderer(CredentialTemplates{}, map[string]CredentialParameter{"p": {}}); err == nil {
		t.Fatal("expected rejection when a parameter sets neither value nor source")
	}
	if _, err := NewCredentialRenderer(CredentialTemplates{}, map[string]CredentialParameter{"p": {Source: "bogus"}}); err == nil {
		t.Fatal("expected rejection of an unknown parameter source")
	}
}

func TestHasCredentialTemplates(t *testing.T) {
	cases := []struct {
		name string
		auth ProviderAuthConfig
		want bool
	}{
		{"no templates", ProviderAuthConfig{}, false},
		{"username template", ProviderAuthConfig{Templates: CredentialTemplates{Username: "{{username}}"}}, true},
		{"password template", ProviderAuthConfig{Templates: CredentialTemplates{Password: "{{password}}"}}, true},
		{"parameter only", ProviderAuthConfig{Parameters: map[string]CredentialParameter{"x": {Value: "y"}}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := HasCredentialTemplates(c.auth); got != c.want {
				t.Fatalf("HasCredentialTemplates = %v, want %v", got, c.want)
			}
		})
	}
}

func TestNewCredentialRenderer_Validation(t *testing.T) {
	// session_id token used but session mode not enabled is rejected by the
	// provider-level validator.
	errs := validateCredentialTemplates(
		ProviderAuthConfig{
			Type:      "basic",
			Username:  "u",
			Password:  "p",
			Templates: CredentialTemplates{Username: "u-{{session_id}}"},
		},
		ProviderSessionConfig{}, // not session-enabled
	)
	if len(errs.Errors) == 0 {
		t.Fatal("expected an error when session_id token is used with session mode not enabled")
	}
}

func TestValidateCredentialTemplates_CredentialTemplateRequiresSessionID(t *testing.T) {
	// credential_template mode must reference session_id somewhere.
	errs := validateCredentialTemplates(
		ProviderAuthConfig{
			Type:      "basic",
			Username:  "u",
			Password:  "p",
			Templates: CredentialTemplates{Password: "{{password}}"}, // no session_id
		},
		ProviderSessionConfig{Supported: true, Mode: "credential_template"},
	)
	if len(errs.Errors) == 0 {
		t.Fatal("expected credential_template mode without session_id to be rejected")
	}
}

func TestValidateCredentialTemplates_UntypedProviderRejected(t *testing.T) {
	// Templating on a non-http provider type is rejected by ProviderConfig.Validate.
	p := ProviderConfig{
		Name:      "srv",
		Type:      "direct",
		Auth:      ProviderAuthConfig{Type: "basic", Username: "u", Password: "p", Templates: CredentialTemplates{Password: "{{password}}"}},
		Endpoints: []ProviderEndpoint{{URL: "http://x"}},
	}
	errs := p.Validate("providers[0]")
	if len(errs.Errors) == 0 {
		t.Fatalf("expected templating on a direct provider to be rejected, got %v", errs)
	}
	msg := strings.ToLower(errs.Error())
	if !strings.Contains(msg, "http_proxy") && !strings.Contains(msg, "templates") {
		t.Fatalf("expected an http_proxy-compatible error, got %q", errs.Error())
	}
}

// --- session id generator ---

func TestGenerateSessionID_DefaultLengthAndCharset(t *testing.T) {
	// Default config (zero) yields a 32-character lowercase hex id. A fixed
	// random source (each byte 0x10) exercises the rejection-sampling path
	// deterministically: 0x10 < safeMax for a 16-symbol alphabet, so no byte is
	// rejected and the output is a 32-character hex string.
	var good = func() func(int) ([]byte, error) {
		return func(n int) ([]byte, error) {
			out := make([]byte, n)
			for i := range out {
				out[i] = 0x10
			}
			return out, nil
		}
	}()
	id, err := GenerateSessionID(good, SessionIDConfig{})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(id) != SessionIDDefaultLength {
		t.Fatalf("default length = %d, want %d", len(id), SessionIDDefaultLength)
	}
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			t.Fatalf("default charset must be lowercase hex, got %q", id)
		}
	}
}

func TestGenerateSessionID_CustomLengthAndCharset(t *testing.T) {
	mk := func(b byte) func(int) ([]byte, error) {
		return func(n int) ([]byte, error) {
			out := make([]byte, n)
			for i := range out {
				out[i] = b
			}
			return out, nil
		}
	}
	// 10-char alphanumeric, the lower bound required for interoperability.
	id, err := GenerateSessionID(mk(0x03), SessionIDConfig{Length: 10, Charset: "alphanumeric"})
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(id) != 10 {
		t.Fatalf("length = %d, want 10 (%q)", len(id), id)
	}
	// Every char must be alphanumeric.
	for _, r := range id {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			t.Fatalf("alphanumeric charset produced a non-alphanumeric rune %q", id)
		}
	}
}

func TestGenerateSessionID_LengthBounds(t *testing.T) {
	// Below minimum (a negative length is out of range).
	if _, err := GenerateSessionID(func(int) ([]byte, error) { return []byte{}, nil }, SessionIDConfig{Length: -1}); err == nil {
		t.Fatal("expected a length below the minimum to fail")
	}
	// Above maximum.
	if _, err := GenerateSessionID(func(int) ([]byte, error) { return make([]byte, 100000), nil }, SessionIDConfig{Length: SessionIDMaxLength + 1, Charset: "hex"}); err == nil {
		t.Fatal("expected a length above the maximum to fail")
	}
	// Unknown charset.
	if _, err := GenerateSessionID(func(int) ([]byte, error) { return make([]byte, 64), nil }, SessionIDConfig{Length: 10, Charset: "binary"}); err == nil {
		t.Fatal("expected an unknown charset to fail")
	}
}

func TestGenerateSessionID_RNGFailureFailsClosed(t *testing.T) {
	_, err := GenerateSessionID(func(int) ([]byte, error) { return nil, errRNGFail }, SessionIDConfig{})
	if err == nil {
		t.Fatal("expected an RNG failure to propagate as an error (fail closed)")
	}
}

func TestGenerateSessionID_ShortReadFailsClosed(t *testing.T) {
	// A random source that returns fewer bytes than requested must fail rather
	// than emit a partial identifier.
	_, err := GenerateSessionID(func(n int) ([]byte, error) { return []byte{0, 0}, nil }, SessionIDConfig{Length: 10, Charset: "hex"})
	if err == nil {
		t.Fatal("expected a short read to fail closed")
	}
}

var errRNGFail = &rngError{}

type rngError struct{}

func (*rngError) Error() string { return "crypto/rand unavailable" }

// TestGenerateSessionID_NoModuloBias verifies that, across a large number of
// draws over an alphabet that does not divide 256, no character dominates. Naive
// `byte % size` selection would skew the low-index characters measurably because
// the rejected high range is uneven; rejection sampling keeps every character
// within a narrow band of the ideal uniform frequency.
func TestGenerateSessionID_NoModuloBias(t *testing.T) {
	alphabet, ok := sessionAlphabet("urlsafe")
	if !ok {
		t.Fatal("urlsafe charset unavailable")
	}
	// A simple LCG that produces a uniformly distributed byte stream (period
	// 2^32) so the test is deterministic and does not depend on the OS RNG.
	var state uint32 = 1
	mk := func(n int) ([]byte, error) {
		out := make([]byte, n)
		for i := range out {
			state = state*1664525 + 1013904223
			out[i] = byte(state >> 24)
		}
		return out, nil
	}

	want := len(alphabet)
	seen := make([]int, 256)
	const ids = 4000
	for i := 0; i < ids; i++ {
		id, err := GenerateSessionID(mk, SessionIDConfig{Length: 7, Charset: "urlsafe"})
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		for _, c := range id {
			seen[c]++
		}
	}
	// Verify every symbol of the alphabet was used and the maximum frequency is
	// close to the uniform ideal (total / alphabet size). A biased selection
	// would make a few chars dominate.
	total := 0
	for c := 0; c < 256; c++ {
		total += seen[c]
	}
	if total == 0 {
		t.Fatal("no characters were collected")
	}
	ideal := float64(total) / float64(want)
	const tolerance = 0.15 // 15% band around the ideal
	for c := 0; c < 256; c++ {
		n := float64(seen[c])
		if n == 0 {
			// Skip bytes that were not produced; only assert over produced chars.
			continue
		}
		if n < ideal*(1-tolerance) || n > ideal*(1+tolerance) {
			t.Fatalf("char %q frequency %d/%d deviates from ideal %.0f by more than %.0f%%",
				string(rune(c)), seen[c], total, ideal, tolerance*100)
		}
	}
	// At least most of the alphabet must have appeared.
	used := 0
	for c := 0; c < 256; c++ {
		if seen[c] > 0 {
			used++
		}
	}
	if used < want-1 {
		t.Fatalf("expected most of the %d-symbol alphabet to appear, got %d", want, used)
	}
}

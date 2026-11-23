package config

import (
	"fmt"
	"strings"
	"unicode"
)

// Generic, provider-independent credential template rendering.
//
// MicroProxy must not hardcode provider-specific credential formats. Instead
// every credential format is expressed as a small, deterministic {{token}}
// template over a fixed, validated input namespace. This file implements that
// renderer, its validation, and the configurable sticky-session identifier
// generator. It contains no provider-name branches and no executable syntax:
// tokens are substituted, never evaluated.
//
// Security contract (see docs/generic-credential-templates.md):
//   - The renderer never executes code, shell commands or expressions.
//   - Tokens are the only variable substitution; everything else is literal text.
//   - Parameter sources are restricted to static config values and a fixed set of
//     endpoint-metadata fields. Downstream client headers can never name a parameter.
//   - An unresolved token or a missing mandatory parameter fails closed: it never
//     silently falls back to the base credential or to direct egress.
//   - Rendered credentials never appear in returned error text, logs, metrics or
//     API responses; errors name the offending token/field, not a value.

// Reserved template tokens, resolved at render time from the rendering context.
const (
	// TokenUsername resolves to the base provider username.
	TokenUsername = "username"
	// TokenPassword resolves to the base provider password.
	TokenPassword = "password"
	// TokenSessionID resolves to the pinned sticky-session identifier. It is only
	// resolvable when the provider is session-enabled.
	TokenSessionID = "session_id"
)

// Parameter sources resolvable at render time from endpoint metadata.
const (
	// SourceEndpointCountry resolves to the selected endpoint's country metadata.
	SourceEndpointCountry = "endpoint.country"
	// SourceEndpointRegion resolves to the selected endpoint's region metadata.
	SourceEndpointRegion = "endpoint.region"
)

// Render bounds. These cap untrusted template/parameter surface area so a
// hostile or accidental config cannot allocate or produce unbounded output.
const (
	// MaxTemplateLen bounds a single username/password template string.
	MaxTemplateLen = 4096
	// MaxParameters bounds the number of named parameters a provider declares.
	MaxParameters = 64
	// MaxRenderedCredLen bounds a single rendered credential field (username or
	// password). Credentials are base64-encoded into headers, so a large field
	// only increases header size; this keeps it bounded and observable.
	MaxRenderedCredLen = 2048
	// MaxParameterValueLen bounds one static parameter value.
	MaxParameterValueLen = 512
)

// EndpointMetadata is the runtime metadata a parameter source may resolve from.
// It is populated from the selected upstream endpoint's static configuration
// (never from client-controlled request headers).
type EndpointMetadata struct {
	Country string
	Region  string
}

// CredentialParameter is one named template parameter. Exactly one of Value or
// Source must be set:
//   - Value: a static, config-provided literal.
//   - Source: a fixed endpoint-metadata field (endpoint.country / endpoint.region).
//
// The reserved names username, password and session_id are not declared here;
// they are always available as built-in tokens.
type CredentialParameter struct {
	Value  string `json:"value,omitempty" yaml:"value,omitempty"`
	Source string `json:"source,omitempty" yaml:"source,omitempty"`
}

// CredentialTemplates holds optional username and password templates. A blank
// field means "use the base credential unmodified." This is what lets a provider
// encode only the password (Evomi-style) or only the username (Bright Data-style)
// purely through configuration.
type CredentialTemplates struct {
	Username string `json:"username,omitempty" yaml:"username,omitempty"`
	Password string `json:"password,omitempty" yaml:"password,omitempty"`
}

// SessionIDConfig configures the per-provider sticky-session identifier
// generator. It has no vendor semantics: the same machinery serves Bright Data,
// Evomi, or any generic provider, and is parameterized only by length and
// character set.
type SessionIDConfig struct {
	// Length is the number of output characters. Bounded to
	// [SessionIDMinLength, SessionIDMaxLength]. Zero selects the default.
	Length int `json:"length,omitempty" yaml:"length,omitempty"`
	// Charset selects the alphabet used. Zero/empty selects "hex" (lowercase
	// hexadecimal), which preserves the legacy 32-character default.
	Charset string `json:"charset,omitempty" yaml:"charset,omitempty"`
}

// Default and bounds for the session identifier generator.
const (
	// SessionIDDefaultLength is the default output length. With the default "hex"
	// charset this yields the legacy 32-character lowercase hexadecimal id
	// (128 bits of entropy: 16 bytes -> 32 hex chars).
	SessionIDDefaultLength = 32
	// SessionIDMinLength is the smallest permitted identifier length.
	SessionIDMinLength = 1
	// SessionIDMaxLength caps the identifier length to bound header size.
	SessionIDMaxLength = 128
)

// sessionIDCharsets is the curated, validated alphabet set. Adding a charset is a
// deliberate code change, never a free-form config value.
var sessionIDCharsets = map[string]string{
	"hex":              "0123456789abcdef",
	"hex_upper":        "0123456789ABCDEF",
	"numeric":          "0123456789",
	"alpha":            "abcdefghijklmnopqrstuvwxyz",
	"alpha_mixed":      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"alphanumeric":     "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
	"alphanumeric_low": "0123456789abcdefghijklmnopqrstuvwxyz",
	"urlsafe":          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
}

// normaliseSessionIDConfig fills defaults and validates the generator
// configuration. An error indicates an out-of-range length, an unknown charset,
// or an empty alphabet, so the caller can fail closed at startup.
func (c SessionIDConfig) normalise() (SessionIDConfig, error) {
	out := c
	if out.Length == 0 {
		out.Length = SessionIDDefaultLength
	}
	if out.Length < SessionIDMinLength {
		return out, fmt.Errorf("session id length %d is below minimum %d", out.Length, SessionIDMinLength)
	}
	if out.Length > SessionIDMaxLength {
		return out, fmt.Errorf("session id length %d exceeds maximum %d", out.Length, SessionIDMaxLength)
	}
	charset := strings.ToLower(strings.TrimSpace(out.Charset))
	if charset == "" {
		charset = "hex"
	}
	// Support a couple of common aliases without widening the open surface.
	switch charset {
	case "hexlower", "hex_lower", "hexadecimal":
		charset = "hex"
	case "alphanum", "alnum":
		charset = "alphanumeric"
	}
	alphabet, ok := sessionIDCharsets[charset]
	if !ok || alphabet == "" {
		return out, fmt.Errorf("session id charset %q is not one of: hex, hex_upper, numeric, alpha, alpha_mixed, alphanumeric, alphanumeric_low, urlsafe", out.Charset)
	}
	out.Charset = charset
	return out, nil
}

// Validate enforces the session identifier generator configuration at startup.
// An empty configuration is valid (it selects the legacy default). A
// misconfiguration (out-of-range length or unknown charset) is rejected so the
// listener fails closed rather than generating an unusable identity.
func (c SessionIDConfig) validate(fieldPath string) *ValidationErrors {
	errs := &ValidationErrors{}
	// Only validate fields that the operator actually set, so partial configs
	// (for example a length without a charset) still use the remaining defaults.
	if c.Length != 0 || strings.TrimSpace(c.Charset) != "" {
		if _, err := c.normalise(); err != nil {
			errs.Add(fieldPath, err.Error())
		}
	}
	return errs
}

// HasConfig reports whether any session identifier generator field is set.
func (c SessionIDConfig) HasConfig() bool {
	return c.Length != 0 || strings.TrimSpace(c.Charset) != ""
}

// sessionAlphabet returns the alphabet for a configured charset.
func sessionAlphabet(charset string) (string, bool) {
	a, ok := sessionIDCharsets[charset]
	return a, ok
}

// GenerateSessionID produces a fresh sticky-session identifier using a
// configurable length and charset. Randomness is drawn from randFn (crypto/rand
// in production, injectable for tests and RNG-failure exercises).
//
// Entropy and collision trade-offs: the identifier carries
// length * log2(len(alphabet)) bits of entropy. Short identifiers (for example a
// 6-character alphanumeric id, ~29 bits) collide with non-negligible probability
// after roughly 2^15 draws (birthday bound). Callers that need a strong sticky
// guarantee should prefer longer identifiers; short identifiers are accepted only
// to interoperate with upstreams that impose tight identifier limits.
//
// Generation avoids modulo bias via per-character rejection sampling and draws
// the random bytes in a single call so it integrates with a single RNG failure.
// It returns an error (never an empty or partial id) on RNG failure so callers
// can fail closed.
func GenerateSessionID(randFn func(int) ([]byte, error), cfg SessionIDConfig) (string, error) {
	normalized, err := cfg.normalise()
	if err != nil {
		return "", err
	}
	alphabet, ok := sessionAlphabet(normalized.Charset)
	if !ok {
		return "", fmt.Errorf("session id charset %q is not supported", normalized.Charset)
	}
	size := len(alphabet)

	// Enough bytes that rejection sampling cannot exhaust the buffer for realistic
	// lengths. Each character consumes on average slightly more than one byte; the
	// 8x margin makes buffer exhaustion astronomically unlikely, and the explicit
	// guard below makes it a clean failure rather than a hang.
	needed := normalized.Length * 8
	raw, err := randFn(needed)
	if err != nil {
		return "", fmt.Errorf("generate session id: %w", err)
	}
	if len(raw) < normalized.Length {
		return "", fmt.Errorf("short random read: got %d bytes, want at least %d", len(raw), normalized.Length)
	}

	// Rejection sampling: the largest multiple of the alphabet size (as a fraction
	// of 256) yields an unbiased byte range; bytes at or above it are discarded.
	safeMax := 256 - (256 % size)
	out := make([]byte, 0, normalized.Length)
	for _, b := range raw {
		if len(out) == normalized.Length {
			break
		}
		if int(b) >= safeMax {
			continue
		}
		out = append(out, string(alphabet[b%byte(size)])[0])
	}
	if len(out) < normalized.Length {
		// Only reachable if nearly every byte was rejected; treat as RNG failure.
		return "", fmt.Errorf("generate session id: insufficient entropy")
	}
	return string(out), nil
}

// --- Credential templates ---

// CredentialRenderContext supplies the dynamic inputs a template may reference.
// Username/Password are the base credentials; SessionID is the pinned identity
// (empty when the provider is not session-enabled); Endpoint is per-endpoint
// static metadata.
type CredentialRenderContext struct {
	Username  string
	Password  string
	SessionID string
	Endpoint  EndpointMetadata
}

// CredentialRenderer renders username and/or password templates over the
// validated input namespace. A blank template field means "use the base
// credential unmodified," so a provider can template only the password, only the
// username, or both.
type CredentialRenderer struct {
	username   *compiledTemplate
	password   *compiledTemplate
	parameters map[string]CredentialParameter
}

// compiledTemplate is a pre-parsed template: literal runs interleaved with
// validated token references. Parsing happens once at construction, so the
// hot path performs only substitution.
type compiledTemplate struct {
	segments  []templateSegment
	tokenRefs []string
}

type templateSegment struct {
	literal string
	token   string // empty when the segment is a literal run
}

// HasTokens reports whether the template references any token.
func (ct *compiledTemplate) HasTokens() bool {
	return len(ct.tokenRefs) > 0
}

// referencesSessionID reports whether the template contains the session_id token.
func (ct *compiledTemplate) referencesSessionID() bool {
	for _, tok := range ct.tokenRefs {
		if tok == TokenSessionID {
			return true
		}
	}
	return false
}

// NewCredentialRenderer compiles and validates the username/password templates
// against the declared parameters. It returns an error for malformed templates,
// unknown tokens, conflicting parameter definitions or out-of-bounds sizes so
// callers can fail closed before any listener starts.
func NewCredentialRenderer(templates CredentialTemplates, parameters map[string]CredentialParameter) (*CredentialRenderer, error) {
	// Validate parameter definitions and build the allowed token namespace.
	if err := validateParameters(parameters); err != nil {
		return nil, err
	}
	allowed := map[string]struct{}{
		TokenUsername:  {},
		TokenPassword:  {},
		TokenSessionID: {},
	}
	for name := range parameters {
		allowed[name] = struct{}{}
	}

	// A blank template compiles to a no-op that emits nothing; rendering then
	// substitutes the base credential for that field.
	usernameTmpl, err := compileTemplate(templates.Username, allowed, "username")
	if err != nil {
		return nil, err
	}
	passwordTmpl, err := compileTemplate(templates.Password, allowed, "password")
	if err != nil {
		return nil, err
	}
	// A blank template string means "use the base credential unmodified." When
	// neither template field is set there is nothing to render even if some
	// parameters are declared, so return a nil renderer. Declared parameters are
	// still validated above.
	if len(templates.Username) == 0 && len(templates.Password) == 0 {
		return nil, nil
	}
	return &CredentialRenderer{
		username:   usernameTmpl,
		password:   passwordTmpl,
		parameters: parameters,
	}, nil
}

// compileTemplate parses a template string into literal runs and validated token
// references. raw == "" yields a template with no segments (renders as empty, so
// the caller substitutes the base credential).
func compileTemplate(raw string, allowed map[string]struct{}, field string) (*compiledTemplate, error) {
	if raw == "" {
		return &compiledTemplate{}, nil
	}
	if len(raw) > MaxTemplateLen {
		return nil, fmt.Errorf("template.%s exceeds %d bytes", field, MaxTemplateLen)
	}
	// ${ENV} expansion already ran on the raw config file; a residual ${ must not
	// be reinterpreted as a variable.
	if strings.Contains(raw, "${") {
		return nil, fmt.Errorf("template.%s must not contain ${ENV} placeholders (env expansion already ran); use {{token}} only", field)
	}

	c := &compiledTemplate{}
	scannable := raw
	for {
		start := strings.Index(scannable, "{{")
		if start < 0 {
			// No more tokens remain. Any closing brace here is unbalanced.
			if strings.Contains(scannable, "}}") {
				return nil, fmt.Errorf("template.%s has unbalanced braces", field)
			}
			if scannable != "" {
				c.segments = append(c.segments, templateSegment{literal: scannable})
			}
			return c, nil
		}
		// Emit any literal text preceding the token.
		if start > 0 {
			c.segments = append(c.segments, templateSegment{literal: scannable[:start]})
		}
		close := strings.Index(scannable[start:], "}}")
		if close < 0 {
			return nil, fmt.Errorf("template.%s has unbalanced braces", field)
		}
		tokenRaw := scannable[start+2 : start+close]
		token := strings.TrimSpace(tokenRaw)
		// A token body may not itself contain braces.
		if strings.ContainsAny(token, "{}") {
			return nil, fmt.Errorf("template.%s has a malformed token", field)
		}
		if token == "" {
			return nil, fmt.Errorf("template.%s has an empty token", field)
		}
		if _, ok := allowed[token]; !ok {
			return nil, fmt.Errorf("template.%s references unknown token %q; declare it under parameters or use a built-in (username, password, session_id)", field, token)
		}
		c.segments = append(c.segments, templateSegment{token: token})
		c.tokenRefs = append(c.tokenRefs, token)
		// Continue scanning after the closing brace.
		scannable = scannable[start+close+2:]
	}
}

// validateParameters enforces the parameter definition contract.
func validateParameters(params map[string]CredentialParameter) error {
	if len(params) > MaxParameters {
		return fmt.Errorf("too many credential parameters (max %d)", MaxParameters)
	}
	for name, p := range params {
		trimmedName := strings.TrimSpace(name)
		if trimmedName == "" {
			return fmt.Errorf("parameter name cannot be empty")
		}
		// Parameter names may not collide with the built-in tokens.
		switch strings.TrimSpace(name) {
		case TokenUsername, TokenPassword, TokenSessionID:
			return fmt.Errorf("parameter %q collides with a built-in token", name)
		}
		hasValue := strings.TrimSpace(p.Value) != ""
		source := strings.TrimSpace(p.Source)
		if hasValue && source != "" {
			return fmt.Errorf("parameter %q must set exactly one of value or source", name)
		}
		if !hasValue && source == "" {
			return fmt.Errorf("parameter %q must set exactly one of value or source", name)
		}
		if hasValue {
			if len(p.Value) > MaxParameterValueLen {
				return fmt.Errorf("parameter %q value exceeds %d bytes", name, MaxParameterValueLen)
			}
			if err := validateCredentialValue(p.Value); err != nil {
				return fmt.Errorf("parameter %q %w", name, err)
			}
			continue
		}
		// source branch
		switch source {
		case SourceEndpointCountry, SourceEndpointRegion:
		default:
			return fmt.Errorf("parameter %q source %q is unknown; supported sources are %s and %s", name, source, SourceEndpointCountry, SourceEndpointRegion)
		}
	}
	return nil
}

// validateCredentialValue rejects control characters and a small unsafe set so a
// rendered credential cannot break the surrounding HTTP structure or inject
// header/body content. Credentials are base64-encoded for basic auth, but we
// keep the raw field sane for any future raw transport and for defensiveness.
func validateCredentialValue(v string) error {
	for _, r := range v {
		switch r {
		case '\t':
			// Tab is tolerated inside a credential field; it is base64-encoded
			// for basic auth and unlikely to break structure.
			continue
		}
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("contains an unsafe HTTP control character")
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("contains an unsafe HTTP control character")
		}
	}
	return nil
}

// Render renders the username and password from the context. A blank template
// field yields the corresponding base credential unmodified. An unresolved
// token, a missing mandatory parameter, or an unsafe rendered value returns an
// error without leaking any credential material.
func (r *CredentialRenderer) Render(ctx CredentialRenderContext) (username, password string, err error) {
	username = ctx.Username
	password = ctx.Password

	if r.username != nil && r.username.HasTokens() {
		rendered, err := r.username.render(ctx, r.parameters)
		if err != nil {
			return "", "", err
		}
		username = rendered
	}
	if r.password != nil && r.password.HasTokens() {
		rendered, err := r.password.render(ctx, r.parameters)
		if err != nil {
			return "", "", err
		}
		password = rendered
	}
	return username, password, nil
}

// render substitutes every token for a single compiled template.
func (ct *compiledTemplate) render(ctx CredentialRenderContext, params map[string]CredentialParameter) (string, error) {
	out := make([]byte, 0, len(ct.segments)*4)
	for _, seg := range ct.segments {
		if seg.token == "" {
			out = append(out, seg.literal...)
			continue
		}
		val, err := resolveToken(seg.token, ctx, params)
		if err != nil {
			return "", err
		}
		out = append(out, val...)
	}
	result := string(out)
	// Defense in depth: no unresolved token may survive substitution. This also
	// catches a token resolving to text that itself contains braces.
	if strings.Contains(result, "{{") || strings.Contains(result, "}}") {
		return "", fmt.Errorf("unresolved template token remains")
	}
	if len(result) > MaxRenderedCredLen {
		return "", fmt.Errorf("rendered credential exceeds %d bytes", MaxRenderedCredLen)
	}
	if err := validateCredentialValue(result); err != nil {
		return "", fmt.Errorf("%w", err)
	}
	return result, nil
}

// resolveToken resolves a single token to its value. session_id is only
// resolvable when the context carries a pinned session identity; a missing
// session identity is a hard error so sticky providers fail closed.
func resolveToken(token string, ctx CredentialRenderContext, params map[string]CredentialParameter) (string, error) {
	switch token {
	case TokenUsername:
		return ctx.Username, nil
	case TokenPassword:
		return ctx.Password, nil
	case TokenSessionID:
		if strings.TrimSpace(ctx.SessionID) == "" {
			return "", fmt.Errorf("session_id token requires a pinned session identity")
		}
		return ctx.SessionID, nil
	}
	p, ok := params[token]
	if !ok {
		// Should be unreachable (validated at compile time), but fail closed.
		return "", fmt.Errorf("unknown token %q", token)
	}
	if strings.TrimSpace(p.Value) != "" {
		return p.Value, nil
	}
	// source branch
	switch p.Source {
	case SourceEndpointCountry:
		if strings.TrimSpace(ctx.Endpoint.Country) == "" {
			return "", fmt.Errorf("source endpoint.country is empty for a required parameter")
		}
		return ctx.Endpoint.Country, nil
	case SourceEndpointRegion:
		if strings.TrimSpace(ctx.Endpoint.Region) == "" {
			return "", fmt.Errorf("source endpoint.region is empty for a required parameter")
		}
		return ctx.Endpoint.Region, nil
	default:
		return "", fmt.Errorf("parameter %q has no resolvable value", token)
	}
}

// referencesSessionIDTokens reports whether any compiled template references the
// session_id token. Used by config validation to require session mode. It
// accounts for declared parameters so a template that mixes a parameter and
// session_id still compiles before the session-id check.
func referencesSessionIDTokens(templates CredentialTemplates, parameters map[string]CredentialParameter) bool {
	allowed := map[string]struct{}{TokenUsername: {}, TokenPassword: {}, TokenSessionID: {}}
	for name := range parameters {
		allowed[name] = struct{}{}
	}
	for _, tmpl := range []string{templates.Username, templates.Password} {
		compiled, err := compileTemplate(tmpl, allowed, "templates")
		if err != nil {
			return false
		}
		if compiled.referencesSessionID() {
			return true
		}
	}
	return false
}

// validateCredentialTemplates validates the templated credential configuration for
// a provider at startup. It enforces:
//   - well-formed templates (no unbalanced braces, no ${ENV}, known tokens),
//   - that session_id is only referenced when the provider is session-enabled,
//   - a basic upstream auth type (rendered credentials become Proxy-Authorization),
//   - non-empty base credentials,
//   - no conflicting legacy/new template definitions.
func validateCredentialTemplates(auth ProviderAuthConfig, session ProviderSessionConfig) *ValidationErrors {
	errs := &ValidationErrors{}
	t := auth.Templates
	hasTemplate := strings.TrimSpace(t.Username) != "" || strings.TrimSpace(t.Password) != ""
	if !hasTemplate && len(auth.Parameters) == 0 {
		return errs // nothing templated; nothing to validate
	}

	// Build the renderer to compile+validate both templates and parameters.
	renderer, err := NewCredentialRenderer(t, auth.Parameters)
	_ = renderer
	if err != nil {
		errs.Add("auth.templates", err.Error())
		return errs
	}

	// A template that references session_id requires a runtime session identity.
	requiresSession := session.SessionEnabled()
	if referencesSessionIDTokens(t, auth.Parameters) {
		if !requiresSession {
			errs.Add("auth.templates", "template references session_id but session mode is not enabled for this provider")
		}
	}
	// Conversely, credential_template mode must actually consume a session id,
	// otherwise rotation cannot change the credential.
	if strings.EqualFold(strings.TrimSpace(session.Mode), "credential_template") {
		if !referencesSessionIDTokens(t, auth.Parameters) {
			errs.Add("session.mode", "credential_template mode requires a template that references session_id")
		}
		if strings.TrimSpace(session.UsernameTemplate) != "" {
			errs.Add("session.username_template", "cannot combine username_template with credential_template mode")
		}
	}
	// username_template mode cannot coexist with generic templating.
	if strings.EqualFold(strings.TrimSpace(session.Mode), "username_template") && hasTemplate {
		errs.Add("auth.templates", "cannot combine auth templates with username_template session mode; use credential_template mode")
	}

	// Templated credentials are delivered as basic Proxy-Authorization, so basic
	// auth with non-empty base credentials is required.
	authType := strings.ToLower(strings.TrimSpace(auth.Type))
	if authType != "basic" {
		errs.Add("auth.type", "credential templates require basic upstream auth")
	} else {
		if strings.TrimSpace(auth.Username) == "" {
			errs.Add("auth.username", "is required for templated basic auth")
		}
		if strings.TrimSpace(auth.Password) == "" {
			errs.Add("auth.password", "is required for templated basic auth")
		}
		// Base credentials must not already contain template tokens; tokens are
		// only substituted from within the configured template.
		if strings.Contains(auth.Username, "{{") || strings.Contains(auth.Username, "}}") {
			errs.Add("auth.username", "base username must not contain template tokens")
		}
		if strings.Contains(auth.Password, "{{") || strings.Contains(auth.Password, "}}") {
			errs.Add("auth.password", "base password must not contain template tokens")
		}
		if strings.Contains(auth.Username, "${") || strings.Contains(auth.Password, "${") {
			errs.Add("auth", "base credentials must not contain ${ENV} placeholders; env expansion already ran")
		}
	}
	return errs
}

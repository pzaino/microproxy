# Generic credential templating

MicroProxy must not hardcode provider-specific credential formats. Every upstream
credential format is instead expressed as a small, deterministic `{{token}}`
template over a fixed, validated input namespace. This document defines the
contract. The implementation lives in `pkg/config/credential.go`.

## Why

Different upstream providers (Evomi, Bright Data, and any generic provider)
encode their basic-auth credentials differently — some encode the password,
some the username, and some both, each with provider-specific delimiters and
ordering. Encoding these as configuration templates (rather than as vendor
branches in code) keeps the renderer provider-independent, testable and reusable
across every http-proxy-compatible provider.

## Security model

- **No execution.** The renderer never evaluates code, shell commands or
  expressions. Tokens are substituted; every other character is literal text.
  There is no scripting, no `${ENV}` interpolation (env expansion already ran on
  the raw config file before parsing), and no brace-recursion.
- **Bounded input surface.** Template length, parameter count, parameter value
  size and rendered-field size are bounded so a hostile or accidental config
  cannot allocate or produce unbounded output.
- **Trusted parameter sources only.** A `{{token}}` parameter resolves from
  either a static config `value` or a fixed endpoint-metadata `source`
  (`endpoint.country` / `endpoint.region`). Downstream client headers can **never**
  name or influence a parameter.
- **Fail closed.** An unresolved token, a missing mandatory parameter/endpoint
  metadata value, or an empty rendered username returns an error and the request
  fails (`502`); it never falls back to the base credential or to direct egress.
- **No leakage.** Rendered credentials never appear in returned error text,
  logs, metrics or API responses. Errors name the offending token/field, not a
  value. Endpoint basic-auth userinfo that a dial/TLS error may echo is redacted
  (`user:****@host`) in any user-visible error message.

## Syntax

Templates are a string of literal runs interleaved with validated `{{token}}`
references. The only built-in tokens are:

| Token          | Meaning                                        |
| -------------- | ---------------------------------------------- |
| `{{username}}` | the base provider username                     |
| `{{password}}` | the base provider password                     |
| `{{session_id}}` | the pinned sticky-session identity         |

Additional parameters are declared under `auth.parameters`. Each parameter
supplies exactly one of `value` (a static literal) or `source` (a fixed
endpoint-metadata field):

- `source: endpoint.country` resolves to the selected endpoint's `country`.
- `source: endpoint.region` resolves to the selected endpoint's `region`.

A blank template field means "use the base credential unmodified," so a provider
can encode only the password, only the username, or both.

## Configuration

### Evomi-style (password only)

The username stays as the base value; the password is encoded with the pinned
session id.

```yaml
providers:
  - name: evomi-residential
    type: http_proxy
    auth:
      type: basic
      username: ${EVOMI_USER}
      password: ${EVOMI_PASSWORD}
      templates:
        password: "{{password}}-{{session_id}}"
    session:
      supported: true
      mode: credential_template
      id:
        length: 10
        charset: alphanumeric
    endpoints:
      - { url: http://gateway.example:8080 }
```

### Bright Data-style (username only)

The password stays as the base value; the username is encoded with the session
id and an endpoint-metadata suffix.

```yaml
providers:
  - name: brightdata-geo
    type: http_proxy
    auth:
      type: basic
      username: ${BD_USER}
      password: ${BD_PASSWORD}
      templates:
        username: "{{username}}.{{session_id}}{{region}}"
      parameters:
        region:
          source: endpoint.region
    session:
      supported: true
      mode: credential_template
    endpoints:
      - { url: http://bd.example:8000, country: US, region: FL }
```

### Fully templated (username and password)

```yaml
auth:
  type: basic
  username: user
  password: pass
  templates:
    username: "{{username}}-{{session_id}}-{{country}}"
    password: "[{{password}}|{{region}}]"
  parameters:
    country: { source: endpoint.country }
    region:  { source: endpoint.region }
session:
  supported: true
  mode: credential_template
```

## Mode selection and constraints

- `session.mode: credential_template` enables per-request rendering.
- `auth.templates` may only be used with basic upstream auth and non-empty base
  credentials.
- A `credential_template` provider must reference `{{session_id}}` somewhere in
  the templates; otherwise rotation cannot change the credential and the config is
  rejected.
- `session.username_template` (legacy mode) and `auth.templates` are mutually
  exclusive — a provider cannot combine them.
- Credential templating is rejected for `direct` and `socks5_proxy` providers
  (the renderer is only consumed where a `Proxy-Authorization` is delivered).

## Session identifier generator

`session.id` configures the sticky identifier:

- `length`: `1..128`; `0`/unset selects the default `32`.
- `charset`: one of `hex` (default, legacy), `hex_upper`, `numeric`, `alpha`,
  `alpha_mixed`, `alphanumeric`, `alphanumeric_low`, `urlsafe`.
- Generation is unbiased (per-character rejection sampling), cryptographically
  random, and fails closed on RNG failure.
- Entropy is `length * log2(alphabet size)`; short identifiers collide
  probabilistically (birthday bound), so prefer longer identifiers for strong
  stickiness.

See `docs/session-control.md` for the rotation/idempotency contract and
configuration that pins identity per instance.

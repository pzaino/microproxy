# MicroProxy sticky/persistent-session control (data plane)

Before starting:

> Note 1: When used with the CROWler (or similar tools),
this feature requires to run a `microproxy` instance per VDI.

> Note 2: This feature requires that the upstream proxy supports 
sticky/persistent sessions.

The instructions below are for setting up and using sticky/persistent 
sessions with MicroProxy and my CROWler setup (but it can be adapted 
for other tools).

Normally you'd want to expose two data-plane entry points sharing the 
same upstream proxy host, zone and password but different upstream
username identities or same identities but different session requirements:

- `:8080` (`edge-http`): rotating residential behavior, unchanged.
- `:8081` (`edge-http-sticky`): sticky residential behavior. One active
  logical session **per MicroProxy instance**, shared by all clients of that
  port.
- `127.0.0.1:8094` (default): data-plane-local session management API,
  authenticated with Bearer by default. It mutates the **running data-plane
  process**, not `microproxy-control` stubs.

## CROWler contract

```
close old browser
POST http://127.0.0.1:8094/api/v1/sessions/rotate
  Authorization: Bearer <MICROPROXY_SESSION_API_KEY>
  Idempotency-Key: <unique-CROWler-job-boundary-id>
wait for 200 {"status":"rotated","provider":"...","generation":N}
start next browser (still via http://<host>:8081)
```

- The acknowledgement means new upstream operations *starting after the commit*
  use the new credentials. It does **not** mean upstream proxy pre-allocated or
  verified a new exit IP.
- Retrying the most recent accepted `Idempotency-Key` while it is still
  retained returns `200 {"status":"rotated",...,"replayed":true}` with the
  original generation, no new identity and no connection cleanup.
- Reusing a retained older key after a newer rotation has committed returns
  `409 {"error":{"code":"stale_idempotency_key",...},
  "original_generation":N,"current_generation":M}`. Stale requests never mutate
  identity or close connections. CROWler must generate a fresh key for each new
  rotation boundary. Keys evicted beyond the bounded retention window are
  treated as new rotations.
- A previously accepted HTTP operation or established CONNECT tunnel may finish
  using its original identity. Callers must close old browsers before rotation.
  Rotation never closes existing tunnels.
- `generation` is process-local and resets on restart. The raw session ID,
  composed username, password and auth headers are never exposed in API output
  or logs.
- Rotation changes the upstream session identity; it **does not guarantee a
  different public IP** or that the upstream proxy retains an IP indefinitely.
- One logical sticky session per VDI. Overlapping independent browser jobs
  needing independent sticky IPs require a future per-client binding feature;
  the global rotation API is insufficient for that.

## Configuration

```yaml
listeners:
  - name: edge-http
    type: http
    address: 0.0.0.0:8080
    provider: proxyservice-residential
    auth_type: none
    enabled: true
  - name: edge-http-sticky
    type: http
    address: 0.0.0.0:8081
    provider: proxyservice-residential-sticky
    auth_type: none
    enabled: true

providers:
  - name: proxyservice-residential
    type: http_proxy
    auth: {type: basic, username: ${LPM_USER}, password: ${LPM_PASSWORD}}
    endpoints: [{url: http://${LPM_SUPERPROXY_DOMAIN}:${LPM_SUPERPROXY_PORT}}]

  - name: proxyservice-residential-sticky
    type: http_proxy
    auth:
      type: basic
      username: ${LPM_USER}   # WITHOUT -session- suffix
      password: ${LPM_PASSWORD}
    session:
      supported: true
      mode: username_template
      username_template: "{{username}}-session-{{session_id}}"
    endpoints: [{url: http://${LPM_SUPERPROXY_DOMAIN}:${LPM_SUPERPROXY_PORT}}]

session_control:
  enabled: true
  address: 127.0.0.1:8094
  auth_type: bearer                    # bearer (default) or none
  bearer_token: ${MICROPROXY_SESSION_API_KEY}
  # allow_unauthenticated_non_loopback: false
  provider: proxyservice-residential-sticky
```

- `listeners[].auth_type` authenticates **downstream clients** connecting to
  the proxy ports. It is unrelated to `session_control.auth_type`, which
  protects the management API. Do not reuse `X-API-Key` control-plane
  credentials here.
- `session_control.auth_type` defaults to `bearer` when omitted. An empty
  `bearer_token` never selects `none`; bearer mode requires a non-empty token
  and fails startup otherwise. `none` is intended for local VDI use and is
  valid only on a loopback address (`127.0.0.1`, `[::1]`, `localhost`). A
  non-loopback unauthenticated bind requires the separate explicit
  `allow_unauthenticated_non_loopback: true` opt-in and should be restricted to
  a protected private network.
- `listeners[].provider` is optional for legacy deployments. When present it is
  a mandatory egress constraint, not a routing preference. `X-Provider-ID`,
  `X-Tenant-ID`, routing rules and `route_override` cannot escape it.
- Only `mode: username_template` with `{{username}}` + `{{session_id}}`
  enables runtime identity. `${...}` must not be used in the template because
  config loading expands env vars; `{{...}}` is runtime-only.
- Base username must omit any existing `-session-` suffix (other
  country/zone parameters are preserved in the base).
- Only `http_proxy`-compatible providers support session mode. `direct` and
  `socks5_proxy` reject it explicitly.
- Required-upstream traffic fails closed (502) on unknown/empty/unhealthy
  endpoints. It never falls back to direct egress. Explicit `direct` providers
  and legacy configs without a binding keep their documented direct behavior.
- A session-enabled provider also fails closed (502) before contacting the
  upstream if the pinned snapshot is missing, empty, belongs to another
  provider, or the username template cannot be rendered. It never falls back to
  the base username. This applies to both HTTP forward requests and CONNECT.
- Startup fails on an enabled API with a missing/empty bearer secret in bearer
  mode, invalid sticky-provider config, duplicate listener names/addresses,
  unsafe unauthenticated non-loopback binding without opt-in, or a session API
  port colliding with enabled listeners, metrics, or another health endpoint.

## Generic credential templating (`mode: credential_template`)

In addition to the legacy `username_template` mode, a provider may render both
the username and the password from base credentials, static parameters and a
pinned session id using a small, provider-independent `{{token}}` template
language. See `docs/generic-credential-templates.md` for the full contract,
security model and examples (Evomi-style password-only, Bright Data-style
username-only, and fully-templated credentials).

Key points:

- `session.mode: credential_template` enables per-request rendering of
  `auth.templates.username` and/or `auth.templates.password`. A blank field means
  "use the base credential unmodified," so a provider can encode only the
  password (Evomi) or only the username (Bright Data) purely in configuration.
- Tokens are substituted, never evaluated: the template is a fixed, validated
  token/literal grammar with **no** script, shell or expression syntax.
- Available built-in tokens are `{{username}}`, `{{password}}`,
  `{{session_id}}`. Additional parameters are declared under
  `auth.parameters`, each with exactly one of a static `value` or a fixed
  endpoint-metadata `source` (`endpoint.country` / `endpoint.region`). Downstream
  client headers can **never** name a parameter.
- `credential_template` mode requires basic upstream auth with non-empty base
  credentials and a template that references `{{session_id}}` (so rotation can
  change the credential). Legacy `username_template` and generic templating are
  mutually exclusive: a provider cannot combine `session.username_template` with
  `auth.templates`.
- Templating is allowed only for http-proxy-compatible providers; `direct` and
  `socks5_proxy` reject it.

### Configurable sticky-session identifier

`session.id` configures the per-provider sticky identity generator:

```yaml
session:
  supported: true
  mode: credential_template
  id:
    length: 6      # 1..128
    charset: alpha # hex (default), hex_upper, numeric, alpha, alpha_mixed,
                   # alphanumeric, alphanumeric_low, urlsafe
```

- A zero/empty `id` selects the legacy default: a 32-character lowercase
  hexadecimal identifier (128 bits of entropy).
- The identifier is generated from `crypto/rand` with no modulo
  bias (per-character rejection sampling) and fails closed on RNG failure.
- Short identifiers (for example a 6-character id, ~29 bits) collide with
  non-negligible probability after roughly 2^15 draws; prefer longer
  identifiers for strong stickiness.

## HTTP contract

`POST /api/v1/sessions/rotate` (data plane, not control plane):

- `Authorization: Bearer <secret>` required in bearer mode (case-insensitive
  scheme, exactly one credential, SHA-256 + constant-time compare).
  `X-API-Key` is a control-plane credential and is rejected here. With
  `auth_type: none`, no credentials are required.
- `Idempotency-Key` required, 1–256 characters from `A-Za-z0-9` plus
  `-_.:~+/=`. Retrying the latest key returns its prior generation with
  `"replayed":true` without rotating; a retained older key returns
  `409 stale_idempotency_key`. State is per-process/provider, bounded
  (512 entries, 24h TTL), and does not survive restart; an evicted key is
  treated as a new rotation.
- Body is ignored and limited to 4KiB.
- `200 {"status":"rotated","provider":"...","generation":N}` on success.
  A latest-key replay also has `"replayed":true`.
- `401` missing/invalid/malformed bearer credentials, `405` wrong method, `400`
  malformed key/request, `409` stale idempotency key (with
  `original_generation` and `current_generation`), `503` RNG failure with no
  state change.
- `GET /api/v1/sessions/status` (authenticated in bearer mode) returns
  `{"provider":"...","generation":N}` without the identity.

Bind loopback by default. `auth_type: none` is rejected on non-loopback
addresses unless `allow_unauthenticated_non_loopback: true` is explicitly set.
For separate network namespace/container deployments prefer bearer auth on a
private network with restricted ingress; do not expose `0.0.0.0` without
controls.

## Operational notes

- Residential peers expire; different session IDs may reuse an IP and restart
  creates a new identity (generation resets to 1).
- In-flight HTTP completes with its pinned identity or begins with the new
  one; identities never mix within one operation. Sticky HTTP disables upstream
  keep-alives so pooled connections cannot reuse old auth; idle connections are
  closed only after a successful new rotation. Replays, stale keys and failed
  rotations never trigger connection cleanup.
- `microproxy-control` `POST /providers/{id}/rotate` and
  `/sessions/{sid}/refresh` remain async contract stubs for the control
  process and do not rotate data-plane sticky identity. See
  `docs/controlplane.md` and `api/session-control.openapi.yaml` (data-plane)
  vs `api/controlplane.openapi.yaml` (control plane).
- Live upstream proxy smoke tests are opt-in only and never run in CI.

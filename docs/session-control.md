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
- `127.0.0.1:8094` (default): authenticated data-plane-local session
  management API. It mutates the **running data-plane process**, not
  `microproxy-control` stubs.

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
  bearer_token: ${MICROPROXY_SESSION_API_KEY}
  provider: proxyservice-residential-sticky
```

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
- Startup fails on an enabled API with missing/empty secret, invalid
  sticky-provider config, duplicate listener names/addresses, or a session API
  port colliding with listeners/observability.

## HTTP contract

`POST /api/v1/sessions/rotate` (data plane, not control plane):

- `Authorization: Bearer <secret>` required (constant-time compare).
  `X-API-Key` is a control-plane credential and is rejected here.
- `Idempotency-Key` required, 1–256 printable ASCII
  (`A-Za-z0-9-_.:~+/=` plus `-_.:~+/=`). Retrying the same key returns its
  prior generation without rotating. State is per-process/provider, bounded
  (512 entries, 24h TTL), and does not survive restart.
- Body is ignored and limited to 4KiB.
- `200 {"status":"rotated","provider":"...","generation":N}` on success.
- `401` missing/invalid credentials, `405` wrong method, `400`
  malformed key/request, `503` RNG failure with no state change.
- `GET /api/v1/sessions/status` (authenticated) returns
  `{"provider":"...","generation":N}` without the identity.

Bind loopback by default. For separate network namespace/container deployments
use a private network, authentication and restricted ingress; do not expose
`0.0.0.0` without controls.

## Operational notes

- Residential peers expire; different session IDs may reuse an IP and restart
  creates a new identity (generation resets to 1).
- In-flight HTTP completes with its pinned identity or begins with the new
  one; identities never mix within one operation. Sticky HTTP disables upstream
  keep-alives so pooled connections cannot reuse old auth; idle connections
  are also closed on rotation.
- `microproxy-control` `POST /providers/{id}/rotate` and
  `/sessions/{sid}/refresh` remain async contract stubs for the control
  process and do not rotate data-plane sticky identity. See
  `docs/controlplane.md` and `api/session-control.openapi.yaml` (data-plane)
  vs `api/controlplane.openapi.yaml` (control plane).
- Live upstream proxy smoke tests are opt-in only and never run in CI.

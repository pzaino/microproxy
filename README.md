# MicroProxy

MicroProxy provides a **data-plane proxy** (`microproxy`) plus a **control-plane API** (`microproxy-control`) so you can route downstream traffic through upstream providers and manage runtime behavior.

## What you run

- `microproxy`: serves downstream proxy listeners from `config.yaml` and exposes observability/health endpoints. VDI profile: `:8080` rotating, `:8081` sticky, `127.0.0.1:8094` session management API (see `docs/session-control.md`).
- `microproxy-control`: serves the control-plane HTTP API (default `:8081` standalone; use a different port such as `:8085` when co-located with the sticky `:8081` data-plane listener) and uses `controlplane.env` for authentication. Its provider rotate/refresh routes are contract stubs and do not mutate data-plane sticky identity.

---

## 1) Build the binaries

From the repository root:

```bash
go build -o bin/microproxy ./cmd/microproxy
go build -o bin/microproxy-control ./cmd/microproxy-control
```

Optional quick version check:

```bash
./bin/microproxy -h
./bin/microproxy-control -h
```

---

## 2) Prepare configuration files

### `config.yaml`

For a direct run on the VDI host, start from the typed example:

```bash
cp deploy/config.example.yaml ./config.yaml
```

For the one-microproxy-per-VDI container topology, start from the focused
container profile instead:

```bash
cp deploy/config.vdi.container.example.yaml ./config.yaml
```

Important fields to review in `config.yaml`:

- `listeners[]`: downstream interfaces (`type`, `address`, auth settings, optional hard `provider` binding).
- `providers[]`: upstream proxies + health checks (`session.mode: username_template` for sticky).
- `routing`: default provider and routing rules by tenant/host.
- `policies`: allow/deny/header policies.
- `tenants`: tenant-to-provider/policy binding.
- `session_control`: VDI-local sticky rotation API (`127.0.0.1:8094` for a host run, `0.0.0.0:8094` on a private container network, `auth_type: bearer` by default, sticky provider). `auth_type: none` is loopback-only unless `allow_unauthenticated_non_loopback: true` is explicitly set. This protects the management API only; listener authentication protects downstream proxy clients.
- `observability.health_endpoints`: liveness/readiness/startup ports. A non-empty `-health-addr` CLI flag overrides `liveness_address`; when omitted, the YAML value is used.

> Tip: the example already includes single-provider, failover, and selenium-friendly scenarios as documented snippets, plus an active sticky VDI profile (`:8080`/`:8081`/`8094`).

### `controlplane.env`

Create runtime auth config for the control-plane API:

```bash
cp deploy/controlplane.env.example ./controlplane.env
```

Recommended production baseline:

```env
MICROPROXY_DEVELOPMENT_MODE=false
MICROPROXY_CONTROLPLANE_API_KEYS=<set-at-least-one-strong-key>
MICROPROXY_CONTROLPLANE_JWTS=
```

Development-only mode (no explicit key set):

- Set `MICROPROXY_DEVELOPMENT_MODE=true`
- The default key becomes: `microproxy-controlplane-dev-key`

### `vdi.env` (data-plane container deployments)

```bash
cp deploy/vdi.env.example ./vdi.env
```

Set a unique `MICROPROXY_SESSION_API_KEY` per VDI plus the upstream endpoint
and base credentials. This is the bearer token CROWler sends to the data-plane
rotation API; it is not a control-plane API key. Keep the file out of version
control.

---

## 3) Run both services directly (without Docker)

Use two terminals.

### Terminal A: data plane

```bash
./bin/microproxy -config ./config.yaml -health-addr :9090
```

`-health-addr` is optional. When non-empty it overrides
`observability.health_endpoints.liveness_address`; when omitted (or blank) the
YAML value is preserved. An override is applied before listeners start and the
effective configuration is validated again, so a collision with enabled
listeners, session control, metrics, or another health endpoint fails startup
with a clear error.

### Terminal B: control plane

```bash
set -a
source ./controlplane.env
set +a
./bin/microproxy-control -config ./config.yaml -listen-addr :8085
```

Use `:8085` (not `:8081`) when microproxy and microproxy-control share a host
network namespace: `:8081` is the sticky data-plane listener in the example
configuration.

---

## 4) Build and run Docker containers

The repository provides `Dockerfile.mp` for `microproxy` and
`Dockerfile.mp-ctrl` for `microproxy-control`.

### 4.1 Build images

```bash
docker build -t microproxy:local -f Dockerfile.mp .
docker build -t microproxy-control:local -f Dockerfile.mp-ctrl .
```

### 4.2 Run one stack per VDI

Copy `deploy/config.vdi.container.example.yaml` to `./config.yaml` and
`deploy/vdi.env.example` to `./vdi.env`, then:

```bash
docker compose up -d --build
```

The data-plane ports are intentionally not published. A sibling CROWler
container on the same compose network uses:

- Selenium/downstream proxy: `http://microproxy:8081`
- Session rotation/status API: `http://microproxy:8094`

Run one compose project per VDI. Never publish `8094`: it mutates that VDI's
upstream identity and is protected only by its bearer token. For a local
reachability check from a distinct container namespace:

```bash
docker compose --profile smoke run --rm vdi-smoke
```

---

## 5) Verify both are running and reachable

### Process/container checks

```bash
# Direct process mode
ps -ef | rg "microproxy|microproxy-control"

# Docker mode
docker compose ps
```

### Health and metrics checks (direct host run)

```bash
curl -i http://127.0.0.1:9090/healthz   # liveness (microproxy)
curl -i http://127.0.0.1:9092/readyz    # readiness (microproxy)
curl -i http://127.0.0.1:9093/startupz  # startup (microproxy)
curl -i http://127.0.0.1:9091/metrics   # prometheus metrics
```

In container mode the data-plane ports are not published. Reach them from a
sibling container at `http://microproxy:9090` … `:9093`, or use
`docker compose --profile smoke run --rm vdi-smoke` for the authenticated
session roundtrip.

### Control-plane reachability/auth checks

Use one of the API keys in `controlplane.env`:

```bash
export API_KEY='<your-key-from-controlplane.env>'
curl -i -H "X-API-Key: ${API_KEY}" http://127.0.0.1:8085/api/v1/health
```

If you are in development mode (`MICROPROXY_DEVELOPMENT_MODE=true` and no configured keys), test with:

```bash
curl -i -H "X-API-Key: microproxy-controlplane-dev-key" http://127.0.0.1:8085/api/v1/health
```

---

## 6) Basic usage workflow

1. Clients send proxy traffic to `microproxy` listener(s): `http://<host>:8080` (rotating) or `:8081` (sticky) for a host run, or `http://microproxy:8080`/`:8081` from a sibling container.
2. `microproxy` routes traffic using `routing` + `tenants` in `config.yaml`.
3. `microproxy-control` exposes API operations for control/inspection (protected by key/JWT auth).
4. Operators monitor health/metrics endpoints and adjust configuration as needed.

---

## Control-plane API guide

For a detailed control-plane usage guide (endpoint catalog, auth/roles, and deployment model), see [controlplane.md](docs/controlplane.md).

## Sticky/persistent-session rotation guide

Microproxy allows the use of a sticky/persistent profile which can be mapped to different ports, e.g., `:8080` rotating, `:8081` sticky, and have a rotation request sent to the data-plane session API (`127.0.0.1:8094` for a host run; `http://microproxy:8094` from a sibling container). See [session-control.md](docs/session-control.md) and `api/session-control.openapi.yaml` for more details.

The rotation API is served by the **data-plane** process that owns the sticky
listener. `microproxy-control`'s provider rotate/refresh routes remain contract
stubs and must not be used by CROWler. Deploy one microproxy process per VDI:
the pinned identity is scoped to the provider and process, not to an individual
browser or source address.

This function (when supported by the upstream proxy) allows rotating of a proxy session on demand without restarting the proxy.

Rotate without restart:

```bash
curl -sS -X POST http://127.0.0.1:8094/api/v1/sessions/rotate \
  -H "Authorization: Bearer ${MICROPROXY_SESSION_API_KEY}" \
  -H "Idempotency-Key: <unique-job-id>"
# {"status":"rotated","provider":"corp-http-sticky","generation":2}
```

Retrying the latest key returns the original generation with
`"replayed": true` and does not rotate again. Reusing a retained older key
after a newer rotation returns `409 stale_idempotency_key` with
`original_generation`/`current_generation`; identity and connections are left
untouched. Keys beyond the bounded retention window (512 entries, 24h) are
treated as new rotations. Generation numbers and idempotency history are
process-local and reset on restart, so CROWler must mint a fresh key after a
proxy restart. With `session_control.auth_type: none`, omit the
`Authorization` header (loopback binding only unless explicitly opted out).

Persistent sessions can help maintain a consistent identity or connection state with the upstream proxy, which is useful for scenarios requiring session affinity or long-lived connections.

> Please note: Persistent sessions rely on the upstream proxy's support for session affinity. If the upstream proxy does not support sticky sessions, the rotation mechanism may not function as expected.

## Contributing

We welcome contributions. Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright Paolo Fabio Zaino, all rights reserved.

Licensed under MPL 2.0. See [LICENSE](LICENSE).

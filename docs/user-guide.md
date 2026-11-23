# MicroProxy: Complete User Guide for Secure, Observable Proxy Operations

MicroProxy is a production-focused proxy platform designed specifically for [theCROWler](https://paolozaino.wordpress.com/portfolio/the-crowler/) and for teams that need to route traffic through one or more upstream proxy providers, apply policy controls, and operate with strong observability.

This guide covers architecture, installation, configuration, security, runtime management, and day-2 operations.

---

## Table of Contents

1. [What MicroProxy Is](#what-microproxy-is)
2. [Core Concepts](#core-concepts)
3. [Architecture and Traffic Flow](#architecture-and-traffic-flow)
4. [Prerequisites](#prerequisites)
5. [Configuration Model Overview](#configuration-model-overview)
6. [Step-by-Step: Build and Run Locally](#step-by-step-build-and-run-locally)
7. [Step-by-Step: Deploy with Docker Compose](#step-by-step-deploy-with-docker-compose)
8. [Control Plane Authentication and Roles](#control-plane-authentication-and-roles)
9. [Control Plane API: Practical Operations](#control-plane-api-practical-operations)
10. [Routing and Policy Design Patterns](#routing-and-policy-design-patterns)
11. [Selenium/Automation-Friendly Mode](#seleniumautomation-friendly-mode)
12. [Health Checks, Metrics, and Monitoring](#health-checks-metrics-and-monitoring)
13. [Production Hardening Checklist](#production-hardening-checklist)
14. [Troubleshooting Guide](#troubleshooting-guide)
15. [Example Production Rollout Plan](#example-production-rollout-plan)
16. [Final Recommendations](#final-recommendations)

---

## What MicroProxy Is

MicroProxy is made of two cooperating services:

- **Data plane service**: (microproxy) receives downstream client proxy traffic and forwards it to upstream providers according to routing and policy rules.
- **Control plane service**: (microproxy-control) exposes an authenticated HTTP API for runtime management and inspection tasks.

This split gives operators a clean boundary:

- Keep traffic movement and traffic control concerns separate.
- Limit human/admin access to the control API only.
- Scale and monitor each service based on its own workload profile.

---

## Core Concepts

Before deployment, align on these terms:

- **Listener**: a downstream entry point (host:port + protocol) where clients connect.
- **Provider**: an upstream proxy definition (or pool) that receives forwarded traffic.
- **Endpoint**: a concrete upstream address inside a provider.
- **Routing rule**: logic that matches request context (such as tenant ID or hostname suffix) and chooses a provider.
- **Policy**: allow/deny or header manipulation behavior applied during request handling.
- **Tenant**: logical identity used to map client groups to allowed providers and policies.
- **Observability endpoints**: liveness/readiness/startup and metrics endpoints used by monitoring and orchestration systems.

---

## Architecture and Traffic Flow

At runtime, traffic generally flows as follows:

1. A client connects to a MicroProxy listener.
2. Listener-level checks run first (authentication, rate limits, protocol handling).
3. Routing rules identify the target provider.
4. Policies execute (allow/deny and optional header processing).
5. Traffic is forwarded to the selected upstream endpoint.
6. Health and metrics data are emitted for operations visibility.

In parallel, operators interact with the control plane API to inspect and manage runtime behavior.

---

## Prerequisites

You can run MicroProxy in local process mode or container mode.

Minimum recommended prerequisites:

- Linux/macOS host or Linux VM
- Go toolchain (for direct binary build path)
- Docker + Docker Compose (for containerized deployment)
- `curl` for verification
- `jq` (optional but useful for JSON responses)

Network and security assumptions:

- You can reach upstream provider endpoints from the MicroProxy runtime.
- Firewall rules permit only intended inbound ports.
- Secrets are injected via environment variables (never hard-coded).

---

## Configuration Model Overview

MicroProxy configuration is organized into the following top-level sections:

- `schema_version`
- `listeners`
- `providers`
- `routing`
- `policies`
- `policy_engine`
- `tenants`
- `session_control`
- `observability`

### 1) Listeners

A listener defines where and how downstream clients connect. Typical fields include:

- `type` (for example HTTP)
- `address` (bind host/port)
- optional auth settings (`auth_type`, `username`, `password`)
- `rate_limit` (requests/second; per-listener token bucket, burst equal to the
  rate. Excess requests receive `429 Too Many Requests` with a `Retry-After`
  header. A value of `0`/omitted disables limiting.)
- `enabled`

### 2) Providers

A provider describes an upstream proxy service and can include:

- provider identity and type
- credentials for upstream auth
- one or more endpoints
- endpoint priority/weight for failover ordering (primary: priority ascending;
  within a priority, weight descending as a deterministic tie-breaker so a high-
  weight endpoint is tried before a low-weight one)
- active health-check settings

### 3) Routing

Routing selects providers by match rules.

Typical strategy:

- Set `default_provider` for unmatched traffic.
- Add explicit rules for critical tenants or hostname suffixes.

Rules are evaluated in order and first-match-wins. Each rule's `match` map may
use any of: `tenant`/`tenant_id`, `provider`/`provider_id`, `host` (exact),
`host_prefix` or `host_suffix` (matched case-insensitively against the proxy
target host, port stripped).

### 4) Policies

Policies enforce traffic governance. Common patterns:

- baseline allow policy
- deny by URL pattern (for content classes)
- deny by response content type
- request header stripping/redaction

### 5) Tenants

Tenants bind identity to allowed providers and policy sets. This is essential for multi-team or multi-customer boundaries.

### 6) Observability

Observability settings expose:

- access logs
- Prometheus-style metrics endpoint
- health endpoints for liveness/readiness/startup
- optional tracing exporter configuration

`-health-addr` is an optional CLI override for
`observability.health_endpoints.liveness_address`. When the flag is omitted or
blank, the YAML value is preserved. When it is non-empty, the override takes
precedence and the effective configuration is validated again before any
listener starts. A port collision with an enabled listener, `session_control`,
metrics, or another health endpoint fails startup with a clear error. Each
configured observability endpoint should use a distinct port; port `0` lets the
kernel choose an ephemeral port.

### 7) Session Control

`session_control` enables the data-plane-local sticky-session management API
(default `127.0.0.1:8094`) used to rotate the upstream identity of a
session-enabled provider without restarting the process:

```yaml
session_control:
  enabled: true
  address: 127.0.0.1:8094
  auth_type: bearer                    # bearer (default) or none
  bearer_token: ${MICROPROXY_SESSION_API_KEY}
  # allow_unauthenticated_non_loopback: false
  provider: corp-http-sticky
```

- `listeners[].auth_type` authenticates downstream proxy clients. It is
  independent from `session_control.auth_type`, which protects only the
  management API. Control-plane `X-API-Key` credentials are not accepted by the
  session API.
- Omitted `session_control.auth_type` means `bearer`. Bearer mode requires a
  non-empty token and rejects missing, invalid, or malformed `Authorization`
  headers with 401. An empty `bearer_token` never implies `none`.
- `auth_type: none` is intended for local VDI use and is valid only on loopback
  (`127.0.0.1`, `[::1]`, `localhost`). Exposing it on a non-loopback address
  requires the separate explicit `allow_unauthenticated_non_loopback: true`
  opt-in and should be restricted to a protected private network.
- `POST /api/v1/sessions/rotate` uses `Idempotency-Key`. A new key advances the
  generation and returns `200 {"status":"rotated",...}`. Replaying the latest
  key returns the original generation with `"replayed":true` and does not
  rotate again or close connections. Reusing a retained older key returns
  `409 stale_idempotency_key` with `original_generation` and
  `current_generation`; identity is unchanged. Keys evicted beyond the bounded
  retention window (512 entries, 24h) are treated as new rotations.
- Rotate the session only after closing the old browser, and start the next
  browser after the 200 acknowledgement. Established CONNECT tunnels survive
  rotation; new requests use the new identity.

See `docs/session-control.md` for the full CROWler contract and
`api/session-control.openapi.yaml` for the API schema.

---

## Step-by-Step: Build and Run Locally

This method runs both services directly on the host.

### Step 1: Build binaries

```bash
go build -o bin/microproxy ./cmd/microproxy
go build -o bin/microproxy-control ./cmd/microproxy-control
```

### Step 2: Create runtime configuration files

```bash
cp deploy/config.example.yaml ./config.yaml
cp deploy/controlplane.env.example ./controlplane.env
```

Then edit both files for your environment.

### Step 3: Set control plane authentication

In `controlplane.env`, set at least one strong API key:

```env
MICROPROXY_DEVELOPMENT_MODE=false
MICROPROXY_CONTROLPLANE_API_KEYS=<strong-key-1>[,<strong-key-2>]
MICROPROXY_CONTROLPLANE_JWTS=
```

Development fallback mode (non-production):

```env
MICROPROXY_DEVELOPMENT_MODE=true
```

If no key is configured in development mode, a default dev key is used. Treat it as insecure and temporary.

### Step 4: Start data plane

```bash
./bin/microproxy -config ./config.yaml -health-addr :9090
```

The flag is optional. If omitted, the liveness address comes from
`observability.health_endpoints.liveness_address` in YAML; a non-empty flag
overrides it. The effective configuration is validated before listeners start,
so conflicting ports fail fast with a clear startup error.

### Step 5: Start control plane

```bash
set -a
source ./controlplane.env
set +a
./bin/microproxy-control -config ./config.yaml -listen-addr :8081
```

### Step 6: Verify service health

```bash
curl -i http://127.0.0.1:9090/healthz
curl -i http://127.0.0.1:9092/readyz
curl -i http://127.0.0.1:9093/startupz
curl -i http://127.0.0.1:9091/metrics
```

Control plane health:

```bash
curl -i http://127.0.0.1:8081/api/v1/health
```

---

## Step-by-Step: Deploy with Docker Compose

For most teams, Compose is the fastest path to repeatable local/staging deployment.

### Step 1: Prepare config and env files

```bash
cp deploy/config.example.yaml ./config.yaml
cp deploy/controlplane.env.example ./controlplane.env
```

Update credentials, endpoints, and security settings.

### Step 2: Build and start

```bash
docker compose up -d --build
```

### Step 3: Confirm containers are healthy

```bash
docker compose ps
docker compose logs --tail=100 microproxy
docker compose logs --tail=100 microproxy-control
```

### Step 4: Validate mapped endpoints

Data plane and observability endpoints (example mappings):

- downstream listener: `:8084`
- liveness: `:8090`
- metrics: `:8091`
- readiness: `:8092`
- startup: `:8093`

Control plane API endpoint (example mapping):

- control API: `:8085`

---

## Control Plane Authentication and Roles

MicroProxy control API supports API key and bearer token auth headers:

- `X-API-Key: <key>`
- `Authorization: Bearer <token>`

Role model:

- **observer**: read-only API access
- **operator**: read access plus provider write operations
- **admin**: full access

Operational best practices:

- assign least privilege by role
- rotate keys on a schedule
- keep separate credentials per environment (dev/stage/prod)
- audit failed auth attempts from logs/metrics

---

## Control Plane API: Practical Operations

Set environment helpers:

```bash
export BASE="http://127.0.0.1:8085"
export API_KEY="<your-api-key>"
```

### Health

```bash
curl -sS "$BASE/api/v1/health" | jq .
```

### List providers

```bash
curl -sS -H "X-API-Key: $API_KEY" "$BASE/api/v1/providers" | jq .
```

### Create provider

```bash
curl -sS -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  "$BASE/api/v1/providers" \
  -d '{
    "provider": {
      "id": "regional-upstream-1",
      "name": "regional-upstream-1",
      "type": "http",
      "endpoint": "http://upstream.example:8080"
    }
  }' | jq .
```

### Replace provider using optimistic concurrency

```bash
RV=$(curl -sS -H "X-API-Key: $API_KEY" "$BASE/api/v1/providers/regional-upstream-1" | jq -r '.provider.resourceVersion')

curl -sS -X PUT \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  "$BASE/api/v1/providers/regional-upstream-1" \
  -d "{\"resourceVersion\":\"$RV\",\"provider\":{\"id\":\"regional-upstream-1\",\"name\":\"regional-upstream-1\",\"type\":\"http\",\"endpoint\":\"http://upstream2.example:8080\"}}" | jq .
```

### Policy dry-run

```bash
curl -sS -X POST \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  "$BASE/api/v1/policies/dry-run" \
  -d '{
    "policyRef": "allow-default",
    "method": "GET",
    "url": "https://example.org/",
    "metadata": {"tenantID": "tenant-single", "provider": "corp-http-primary"}
  }' | jq .
```

---

## Routing and Policy Design Patterns

### Pattern A: Single upstream baseline

Use one provider as default while you validate stability, latency, and auth.

### Pattern B: Critical-traffic failover

Create a backup provider and route selected tenant/host traffic there when needed.

### Pattern C: Content governance

Use layered deny policies:

- URL-pattern deny
- content-type deny

This catches both explicit file extensions and opaque dynamic URLs.

### Pattern D: Header hygiene

Apply request header stripping for sensitive fields when crossing trust boundaries.

---

## Selenium/Automation-Friendly Mode

For browser automation use cases, teams often prefer relaxed downstream auth while preserving upstream controls.

Typical approach:

- listener auth disabled for automation clients
- upstream provider auth remains enabled
- tenant/routing boundaries still enforced
- observability fully enabled for auditability

Use only in constrained environments with network segmentation and strong monitoring.

---

## Health Checks, Metrics, and Monitoring

A robust monitoring baseline should include:

- **Liveness**: process is alive.
- **Readiness**: service can accept traffic safely.
- **Startup**: startup sequence complete.
- **Metrics**: scrape regularly and alert on errors/latency.

Recommended alerts:

- readiness failures over rolling windows
- sustained upstream health-check failures
- policy-deny spikes (possible abuse or misconfiguration)
- authentication failures at control API

---

## Production Hardening Checklist

Use this checklist before go-live:

- [ ] Development mode disabled
- [ ] Strong API keys/tokens configured
- [ ] Secrets injected via environment or secret store
- [ ] TLS termination enforced at ingress/edge
- [ ] Firewall rules restricted to required ports
- [ ] Health endpoints integrated with orchestrator probes
- [ ] Metrics integrated with dashboards and alerting
- [ ] Provider health checks tuned (interval/timeout/threshold)
- [ ] Tenant-to-provider boundaries validated
- [ ] Deny policies tested with dry-run and real traffic samples
- [ ] Runbook prepared for failover and key rotation

---

## Troubleshooting Guide

### Symptom: 401/403 on control API

Check:

- wrong or missing `X-API-Key`/Bearer token
- key role lacks required privilege
- development mode assumptions conflicting with production settings

### Symptom: downstream clients cannot connect

Check:

- listener bind address and port mapping
- container port exposure
- firewall/network policy
- listener auth credentials

### Symptom: traffic reaches proxy but upstream fails

Check:

- provider endpoint reachability (DNS, route, firewall)
- upstream credentials
- health-check thresholds too aggressive
- routing rules selecting unexpected provider

### Symptom: expected deny policy not firing

Check:

- tenant-policy binding
- regex selector correctness
- policy order and chain behavior
- metadata values used for routing/policy evaluation

---

## Example Production Rollout Plan

1. **Phase 1 (staging):** single provider + baseline allow policy + full observability.
2. **Phase 2:** add content governance policies and validate false-positive rate.
3. **Phase 3:** enable backup provider and failover routing for critical tenants.
4. **Phase 4:** enforce role-separated control-plane credentials and rotation policy.
5. **Phase 5:** scale horizontally and standardize dashboards/alerts.

---

## Final Recommendations

- Start simple: one provider, one tenant, baseline policy.
- Add controls incrementally: deny policies, failover, role-split auth.
- Treat observability as mandatory, not optional.
- Keep config and credential management disciplined across environments.

With this operating model, MicroProxy can become a reliable control point for secure, policy-aware proxy routing in development, staging, and production.

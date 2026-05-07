# MicroProxy Control Plane (`microproxy-control`) — User Guide

This guide explains how `microproxy-control` interacts with `microproxy`, how to call the API, and how to deploy one-vs-many control planes.

## Architecture and control model

`microproxy` and `microproxy-control` are two separate processes:

- **`microproxy`** is the data plane. It accepts downstream proxy traffic and forwards it to upstream providers based on runtime resolver/registry/policy components.
- **`microproxy-control`** is an HTTP API process. It loads the same config shape, serves `/api/v1/*`, and can mutate **its own in-memory runtime components** (provider store + resolver + registry + policy engine).

Important behavior today:

- There is no built-in remote agent/gRPC channel from `microproxy-control` to a separate `microproxy` process.
- Runtime updates performed via `microproxy-control` are applied in the control process runtime state.
- `microproxy` keeps using its own runtime state loaded from `config.yaml` at startup.

So, today, the control plane API is best understood as a management API for the control process runtime model and provider state, not a distributed fleet orchestrator.

## Does one control plane manage a fleet?

**Current answer: no (not natively).**

A single `microproxy-control` instance does not discover or push configuration into multiple independent `microproxy` containers by itself.

If you run multiple `microproxy` instances, you currently need external orchestration (for example your deployment system) to keep their configs aligned and to restart/reload them as needed.

## Authentication and authorization

All `/api/v1/*` endpoints except `GET /api/v1/health` require auth.

Supported credentials:

- `X-API-Key: <key>`
- `Authorization: Bearer <token>`

Environment variables:

- `MICROPROXY_CONTROLPLANE_API_KEYS` — comma-separated API keys; optional role syntax: `key=observer|operator|admin`
- `MICROPROXY_CONTROLPLANE_JWTS` — comma-separated bearer tokens with optional role syntax
- `MICROPROXY_DEVELOPMENT_MODE=true` — if no API keys are set, enables default dev key `microproxy-controlplane-dev-key`

Role permissions:

- **observer**: read-only (`GET`)
- **operator**: `GET` + provider write routes (`/api/v1/providers*`)
- **admin**: all routes/methods

## API endpoint catalog

Base URL examples:

- local direct run: `http://127.0.0.1:8081`
- docker-compose sample mapping: `http://127.0.0.1:8085`

### 1) Health and config

- `GET /api/v1/health` — unauthenticated health status for control service.
- `GET /api/v1/config` — returns sanitized config view (secrets redacted).

### 2) Providers (implemented)

- `GET /api/v1/providers` — list providers with health snapshot.
- `POST /api/v1/providers` — create provider.
- `GET /api/v1/providers/{providerID}` — fetch one provider.
- `PUT /api/v1/providers/{providerID}` — full replace (requires `resourceVersion`).
- `PATCH /api/v1/providers/{providerID}` — partial update for supported fields (`name`, `type`, `endpoint`) and `resourceVersion`.
- `DELETE /api/v1/providers/{providerID}?resourceVersion=...` (or `If-Match`) — delete with optimistic concurrency.
- `POST /api/v1/providers/{providerID}/rotate` — async operation stub/contract route.
- `POST /api/v1/providers/{providerID}/sessions/{sid}/refresh` — async operation stub/contract route.
- `GET /api/v1/providers/{providerID}/capabilities` — provider capability view.

### 3) Operations (implemented)

- `GET /api/v1/operations/{operationID}` — check async operation status.

### 4) Policies

- `POST /api/v1/policies/dry-run` — evaluate a policy decision against synthetic request metadata.
- `GET /api/v1/policies`
- `GET /api/v1/policies/{policyID}`

### 5) Reserved/stub collection routes

These exist to preserve API contract shape and currently return empty/not-implemented payloads:

- `GET /api/v1/routing`
- `GET /api/v1/routing/{routeID}`
- `GET /api/v1/tenants`
- `GET /api/v1/tenants/{tenantID}`
- `GET /api/v1/sessions`
- `GET /api/v1/sessions/{sessionID}`

## Practical usage examples

Set API key:

```bash
export API_KEY='<your-key>'
BASE='http://127.0.0.1:8085'
```

Health:

```bash
curl -sS "$BASE/api/v1/health" | jq .
```

List providers:

```bash
curl -sS -H "X-API-Key: $API_KEY" "$BASE/api/v1/providers" | jq .
```

Create provider:

```bash
curl -sS -X POST -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  "$BASE/api/v1/providers" \
  -d '{
    "provider": {
      "id": "new-provider",
      "name": "new-provider",
      "type": "http",
      "endpoint": "http://upstream.example:8080"
    }
  }' | jq .
```

Replace provider (note `resourceVersion`):

```bash
RV=$(curl -sS -H "X-API-Key: $API_KEY" "$BASE/api/v1/providers/new-provider" | jq -r '.provider.resourceVersion')

curl -sS -X PUT -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  "$BASE/api/v1/providers/new-provider" \
  -d "{\"resourceVersion\":\"$RV\",\"provider\":{\"id\":\"new-provider\",\"name\":\"new-provider\",\"type\":\"http\",\"endpoint\":\"http://upstream2.example:8080\"}}" | jq .
```

Policy dry-run:

```bash
curl -sS -X POST -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  "$BASE/api/v1/policies/dry-run" \
  -d '{
    "policyRef": "allow-default",
    "method": "GET",
    "url": "https://example.org/",
    "metadata": {"tenantID": "tenant-a", "provider": "default"}
  }' | jq .
```

## Deployment guidance right now

If you need independent per-proxy runtime control, deploy one `microproxy-control` alongside each `microproxy` instance and target each control API endpoint explicitly.

If you need fleet-wide control from one place, add an external orchestrator layer (your own service or deployment tooling) that fans out API/config operations across instances.

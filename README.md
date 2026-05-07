# MicroProxy

MicroProxy provides a **data-plane proxy** (`microproxy`) plus a **control-plane API** (`microproxy-control`) so you can route downstream traffic through upstream providers and manage runtime behavior.

## What you run

- `microproxy`: serves downstream proxy listeners from `config.yaml` and exposes observability/health endpoints.
- `microproxy-control`: serves the control-plane HTTP API (default `:8081`) and uses `controlplane.env` for authentication.

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

Start from the typed example:

```bash
cp deploy/config.example.yaml ./config.yaml
```

Important fields to review in `config.yaml`:

- `listeners[]`: downstream interfaces (`type`, `address`, auth settings).
- `providers[]`: upstream proxies + health checks.
- `routing`: default provider and routing rules by tenant/host.
- `policies`: allow/deny/header policies.
- `tenants`: tenant-to-provider/policy binding.
- `observability.health_endpoints`: liveness/readiness/startup ports.

> Tip: the example already includes single-provider, failover, and selenium-friendly scenarios as documented snippets.

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

---

## 3) Run both services directly (without Docker)

Use two terminals.

### Terminal A: data plane

```bash
./bin/microproxy -config ./config.yaml -health-addr :9090
```

### Terminal B: control plane

```bash
set -a
source ./controlplane.env
set +a
./bin/microproxy-control -config ./config.yaml -listen-addr :8081
```

---

## 4) Build and run Docker containers

The repository `Dockerfile` builds `microproxy`. For `microproxy-control`, use a small companion Dockerfile.

### 4.1 Build `microproxy` image

```bash
docker build -t microproxy:local -f Dockerfile .
```

### 4.2 Build `microproxy-control` image

Create `Dockerfile.control`:

```dockerfile
FROM golang:1.24-alpine AS builder
WORKDIR /src

ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT} go build -o /out/microproxy-control ./cmd/microproxy-control

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/microproxy-control /usr/local/bin/microproxy-control
ENTRYPOINT ["/usr/local/bin/microproxy-control"]
CMD ["-config", "/etc/microproxy/config.yaml", "-listen-addr", ":8081"]
```

Build it:

```bash
docker build -t microproxy-control:local -f Dockerfile.control .
```

### 4.3 Run containers together

Example `docker-compose.yml`:

```yaml
services:
  microproxy:
    image: microproxy:local
    container_name: microproxy
    env_file:
      - ./controlplane.env
      #- ../thecrowler/.env  # if you want to share env vars with the CROWler project
    ports:
      - "8084:8080" # downstream proxy listener
      - "8090:8090" # liveness
      - "8091:8091" # metrics
      - "8092:8092" # readiness
      - "8093:8093" # startup
    volumes:
      - ./config.yaml:/etc/microproxy/config.yaml:ro
    command: ["-config", "/etc/microproxy/config.yaml", "-health-addr", ":9090"]

  microproxy-control:
    image: microproxy-control:local
    container_name: microproxy-control
    env_file:
      - ./controlplane.env
      #- ../thecrowler/.env  # if you want to share env vars with the CROWler project
    ports:
      - "8085:8081" # control-plane API
    volumes:
      - ./config.yaml:/etc/microproxy/config.yaml:ro
    command: ["-config", "/etc/microproxy/config.yaml", "-listen-addr", ":8081"]
```

Start:

```bash
docker compose up -d
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

### Health and metrics checks

```bash
curl -i http://127.0.0.1:8090/healthz   # liveness (microproxy)
curl -i http://127.0.0.1:8092/readyz    # readiness (microproxy)
curl -i http://127.0.0.1:8093/startupz  # startup (microproxy)
curl -i http://127.0.0.1:8091/metrics   # prometheus metrics
```

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

1. Clients send proxy traffic to `microproxy` listener(s), for example `http://<host>:8084`.
2. `microproxy` routes traffic using `routing` + `tenants` in `config.yaml`.
3. `microproxy-control` exposes API operations for control/inspection (protected by key/JWT auth).
4. Operators monitor health/metrics endpoints and adjust configuration as needed.

---

## Control-plane API guide

For a detailed control-plane usage guide (endpoint catalog, auth/roles, and deployment model), see [controlplane.md](docs/controlplane.md).

## Contributing

We welcome contributions. Please read [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Copyright Paolo Fabio Zaino, all rights reserved.

Licensed under MPL 2.0. See [LICENSE](LICENSE).

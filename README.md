# MicroProxy

MicroProxy is a multi-vendor, downstream proxy node designed for the CROWler. It facilitates seamless communication between various proxy vendors and the CROWler, ensuring efficient data collection and processing.

## Features

- **Multi-vendor Support**: Connects with multiple vendors to aggregate data.
- **Downstream Proxy**: Acts as an intermediary to streamline data flow.
- **Efficient Data Handling**: Optimized for high-performance data processing.

## Installation

To install and build MicroProxy, follow these steps:

```bash
git clone https://github.com/pzaino/microproxy.git
cd microproxy
go build -o microproxy ./cmd/microproxy
```

## Usage

Run the MicroProxy server with the following command:

```bash
./microproxy -config ./config.yaml -health-addr :9090
```

You can also run directly from source:

```bash
go run ./cmd/microproxy -config ./config.yaml -health-addr :9090
```

Flags:

- `-config`: path to a configuration file (`.yaml`, `.yml`, or `.json`).
- `-health-addr`: health endpoint listen address (default `:9090`).

### Typed configuration examples and profiles

A versioned, fully commented typed config template is available at `deploy/config.example.yaml`.

Deployment profiles are available under `deploy/profiles/`:

- `local-development.yaml`
- `single-upstream-production.yaml`
- `multi-provider-failover.yaml`
- `mixed-http-socks5.yaml`

For migration from legacy `microproxy`/`upstream_proxy` sections to typed root sections, see `docs/migration.md` (includes side-by-side examples).

### Control-plane authentication environment variables

The control-plane API requires explicit authentication configuration unless development mode is deliberately enabled.

- `MICROPROXY_CONTROLPLANE_API_KEYS`: Comma-separated API keys accepted through `X-API-Key`.
- `MICROPROXY_CONTROLPLANE_JWTS`: Comma-separated bearer tokens accepted through `Authorization: Bearer <token>`.
- `MICROPROXY_DEVELOPMENT_MODE`: Optional boolean (`true|false`, `1|0`, `yes|no`, `on|off`).  
  When `true`, and no API keys are provided, MicroProxy enables a development-only default key: `microproxy-controlplane-dev-key`.

Production deployments should keep `MICROPROXY_DEVELOPMENT_MODE=false` and set at least one value in either `MICROPROXY_CONTROLPLANE_API_KEYS` or `MICROPROXY_CONTROLPLANE_JWTS`.

## Production readiness

MicroProxy is currently in active development and is not yet production-ready.

## Contributing

We welcome contributions! Please read our [contributing guidelines](CONTRIBUTING.md) for more details.

## License

This project is copyright by Paolo Fabio Zaino, all rights reserved.

This project is licensed under the MPL 2.0 License. See the [LICENSE](LICENSE) file for details.

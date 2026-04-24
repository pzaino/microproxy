# MicroProxy

MicroProxy is a multi-vendor, downstream proxy node designed for the CROWler. It facilitates seamless communication between various vendors and the CROWler, ensuring efficient data collection and processing.

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

## Contributing

We welcome contributions! Please read our [contributing guidelines](CONTRIBUTING.md) for more details.

## License

This project is copyright by Paolo Fabio Zaino, all rights reserved.

This project is licensed under the MPL 2.0 License. See the [LICENSE](LICENSE) file for details.

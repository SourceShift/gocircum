# gocircum

<p align="center">
  <img src="assets/gocircum.png" alt="gocircum logo" width="200"/>
</p>

[![Build Status](https://img.shields.io/github/actions/workflow/status/SourceShift/gocircum/main.yml?branch=main)](https://github.com/SourceShift/gocircum/actions/workflows/main.yml)
[![Go Report Card](https://img.shields.io/go/report-card/github.com/SourceShift/gocircum)](https://goreportcard.com/report/github.com/SourceShift/gocircum)
[![codecov](https://codecov.io/gh/SourceShift/gocircum/branch/main/graph/badge.svg?token=E6QKRQJHXY)](https://codecov.io/gh/SourceShift/gocircum)
[![license](https://img.shields.io/github/license/SourceShift/gocircum)](https://github.com/SourceShift/gocircum/blob/master/LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/SourceShift/gocircum?label=Release)](https://github.com/SourceShift/gocircum/releases)

A modular and adaptable censorship circumvention framework designed for resilience against sophisticated network adversaries.

---

## Table of Contents

- [Vision](#vision)
- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Key Features](#key-features)
- [Architecture Overview](#architecture-overview)
- [Getting Started](#getting-started)
  - [Installation](#installation)
- [Usage (CLI)](#usage-cli)
  - [Testing Strategies](#testing-strategies)
  - [Running the Proxy](#running-the-proxy)
- [Configuration](#configuration)
- [Security](#security)
  - [Maintained Dependencies](#maintained-dependencies)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Vision

To empower individuals living under internet censorship with a resilient, adaptable, and user-friendly tool to access the global internet freely and securely.

## The Problem

State-level censorship systems use Deep Packet Inspection (DPI) to identify and block circumvention tools by fingerprinting their network traffic, particularly the initial TLS `ClientHello` message. Many existing tools can be rigid and quickly become obsolete as censors adapt their blocking strategies.

## The Solution

**gocircum** is a modular framework built around a core Go library. It allows for the rapid definition, testing, and deployment of new evasion techniques. Its key features are designed to counter adaptive censorship:

- **Configurable Evasion Strategies**: Instead of hardcoded logic, `gocircum` uses a simple YAML file (`strategies.yaml`) to define how it should disguise traffic. This allows users and researchers to quickly adapt to new blocking methods without needing to recompile the application. **Crucially, all strategies enforce domain fronting to prevent SNI-based blocking.**
- **Automated Strategy Ranking**: For non-technical users, the framework can automatically test which evasion strategies are currently working and select the best one. This provides a simple "one-click" experience.
- **Multiple Frontends**: The core library powers different applications for different users:
    - A powerful **Command-Line Interface (CLI)** for technical users to test networks and run a local proxy.
    - **Mobile library bindings** to enable the creation of simple, one-click apps for Android and iOS.

## Key Features

- **YAML-based Strategies**: Define complex evasion profiles in a simple text file.
  - **Mandatory Domain Fronting**: All strategies are enforced to use domain fronting, hiding the true destination from network observers by separating the TLS SNI from the HTTP Host header.
  - **ClientHello Fragmentation**: Obfuscate the TLS handshake by fragmenting the `ClientHello` packet with configurable sizing and delays.
  - **uTLS Fingerprinting**: Mimic popular browser fingerprints (Chrome, Firefox, Safari) to blend in with normal traffic using `uTLS`.
- **Automated Strategy Ranking**: The `test` command probes all defined strategies against real-world domains and ranks them by success and latency, finding the optimal path for the current network conditions.
- **Secure DNS Resolution**: All internal DNS lookups are performed over DNS-over-HTTPS (DoH) using domain-fronted providers to prevent DNS-based blocking and leaks.
- **Cross-Platform CLI (`gocircum-cli`)**: A powerful command-line tool for testing, debugging, and running a local SOCKS5 proxy on Windows, macOS, and Linux.
- **Mobile-Ready Library**: The core engine is designed to be compiled as a mobile library (`.aar` for Android, `.xcframework` for iOS) for easy integration into mobile apps.

## Architecture Overview

The project is structured for modularity and ease of extension:

```
gocircum/
├── cli/            # Command-line interface entry point
├── core/           # The heart of the engine
│   ├── api.go      # High-level engine API
│   ├── config/     # YAML configuration loading and validation
│   ├── engine/     # Connection and transport factory logic
│   ├── proxy/      # SOCKS5 server and secure DoH resolver
│   └── ranker/     # Strategy testing and ranking logic
├── mobile/         # Bindings for mobile applications
├── interfaces/     # Public Go interfaces for the engine
├── pkg/            # Shared utility packages (e.g., logging)
└── strategies.yaml # Default evasion strategy definitions
```

## Getting Started

### Installation

#### From Pre-compiled Binaries (Recommended)

You can download the latest pre-compiled `gocircum-cli` binary for your operating system from the [**GitHub Releases**](https://github.com/SourceShift/gocircum/releases) page.

#### From Source

**Prerequisites:**
- [Go](https://go.dev/doc/install) (version 1.21+)
- `make`

1.  **Clone the repository:**
    ```sh
    git clone https://github.com/SourceShift/gocircum.git
    cd gocircum
    ```

2.  **Build the CLI:**
    ```sh
    make build-cli
    ```
    The binary will be available at `./bin/gocircum-cli`. You can move it to your system's PATH for easier access:
    ```sh
    sudo mv ./bin/gocircum-cli /usr/local/bin/
    ```

## Usage (CLI)

The `gocircum-cli` provides two main subcommands: `test` and `proxy`.

### Testing Strategies

The `test` command runs through all strategies defined in `strategies.yaml` and reports their performance. This is useful for understanding which evasion techniques work on your current network.

**Command:**
```sh
gocircum-cli test --config strategies.yaml
```

**Example Output:**
```
ID                               SUCCESS  LATENCY    DESCRIPTION
df_google_utls_chrome            OK       98.123ms   Domain Fronting via Google with uTLS Chrome
df_google_fragment_utls_firefox  OK       154.456ms  Domain Fronting (Google) with fragmentation and uTLS Firefox
df_amazon_utls_chrome            FAIL     0s         Domain Fronting via Amazon with uTLS Chrome
...
```

### Running the Proxy

The `proxy` command starts a local SOCKS5 proxy. You can either specify a strategy by its ID or let the engine automatically find and use the best one.

**Run with the best available strategy:**
(The engine will first run tests to find the fastest working strategy)
```sh
gocircum-cli proxy
INFO Starting SOCKS5 proxy address=127.0.0.1:1080
```

**Run with a specific strategy ID:**
```sh
gocircum-cli proxy --strategy df_google_utls_chrome
INFO SOCKS5 proxy listening address=127.0.0.1:1080
```

**Run on a different address:**
```sh
gocircum-cli proxy --addr 127.0.0.1:9050
```

Once running, configure your applications to use the SOCKS5 proxy at `127.0.0.1:1080` (or the address you specified).

## Configuration

The framework's behavior is entirely controlled by `strategies.yaml`.

```yaml
# DNS-over-HTTPS providers used for secure, internal DNS resolution.
# At least one is required. They can also use domain fronting.
doh_providers:
  - name: "Cloudflare"
    url: "https://dns.cloudflare.com/dns-query"
    server_name: "dns.cloudflare.com" # The real DoH server name (for the Host header)
    bootstrap: ["1.1.1.1:443", "1.0.0.1:443"] # Hardcoded IPs to avoid initial DNS lookup

# A list of high-availability domains to test strategies against.
canary_domains:
  - "www.cloudflare.com"
  - "www.google.com"

# A list of evasion strategies (fingerprints).
fingerprints:
  - id: "df_google_utls_chrome"
    description: "Domain Fronting via Google with uTLS Chrome"
    # Domain fronting is mandatory for all strategies.
    domain_fronting:
      enabled: true
      front_domain: "www.google.com:443" # The "benign" domain for the TLS SNI.
      covert_target: "www.youtube.com" # The domain for the encrypted HTTP Host header.
    # Low-level transport configuration.
    transport:
      protocol: "tcp" # Can be "tcp" or "quic".
      # Optional fragmentation of the initial data packet (ClientHello).
      fragmentation:
        algorithm: "static" # "static" (uses packet_sizes) or "even" (divides into N chunks).
        packet_sizes:
          - [10, 20]   # Send a chunk of 10-20 bytes.
          - [30, 50]   # Then send a chunk of 30-50 bytes.
        delay_ms: [5, 15] # Wait 5-15ms between sending chunks.
    # TLS layer configuration.
    tls:
      library: "utls" # Enforced to be "utls" to avoid fingerprinting.
      client_hello_id: "HelloChrome_Auto" # Mimics a Chrome browser's ClientHello.
      min_version: "1.3"
      max_version: "1.3"
```

## Security

### Maintained Dependencies

The project prioritizes security by ensuring that all third-party dependencies are properly maintained and secure. In particular:

- **SOCKS5 Implementation**: We maintain our own fork of the SOCKS5 library (`github.com/gocircum/go-socks5-maintained`) based on the original `github.com/armon/go-socks5` codebase. Our maintained fork undergoes regular security audits and receives updates to address potential vulnerabilities that might exist in the original unmaintained repository (last updated in 2016).

- **Security Audits**: All critical dependencies are regularly reviewed for security vulnerabilities and actively maintained.

- **Dependency Upgrades**: When an unmaintained dependency is identified, it is immediately forked, audited, and replaced with a maintained version under our organization's control.

If you identify any security concerns with our dependencies, please report them through our security vulnerability disclosure process.

## Development

**Prerequisites:**
- [Go](https://go.dev/doc/install) (version 1.21+)
- `make`
- `gomobile` and `golangci-lint`

1.  **Install dependencies:**
    ```sh
    make install-deps
    ```

2.  **Run tests:**
    ```sh
    make test
    ```

3.  **Run tests with the race detector:**
    ```sh
    make test-race
    ```

4.  **Lint the codebase:**
    ```sh
    make lint
    ```

## Contributing

Contributions are highly welcome! Whether you're adding new evasion strategies, improving the core library, or fixing bugs, your help is valuable. Please feel free to open an issue or submit a pull request.

1.  **Fork the repository.**
2.  **Create a new branch:** `git checkout -b feature/your-feature-name`
3.  **Make your changes.**
4.  **Run tests and lint:** `make test && make lint`
5.  **Commit your changes:** `git commit -m "feat: Describe your feature"`
6.  **Push to the branch:** `git push origin feature/your-feature-name`
7.  **Open a pull request.**

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
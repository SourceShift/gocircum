# gocircum

A modular censorship circumvention framework designed to be resilient and adaptable.

---

## Vision

To empower individuals living under internet censorship with a resilient, adaptable, and user-friendly tool to access the global internet freely and securely.

## The Problem

State-level censorship systems use Deep Packet Inspection (DPI) to identify and block circumvention tools by fingerprinting their network traffic, particularly the initial TLS ClientHello message. Existing tools can be rigid and quickly become obsolete as censors adapt their blocking strategies.

## The Solution

**gocircum** is a modular framework built around a core Go library. It allows for the rapid definition, testing, and deployment of new evasion techniques. Its key features are designed to counter adaptive censorship:

- **Configurable Evasion Strategies**: Instead of hardcoded logic, `gocircum` uses a simple YAML file (`strategies.yaml`) to define how it should disguise traffic. This allows users and researchers to quickly adapt to new blocking methods without needing to recompile the application.
- **Automated Strategy Ranking**: For non-technical users, the framework can automatically test which evasion strategies are currently working and select the best one. This provides a simple "one-click" experience.
- **Multiple Frontends**: The core library powers different applications for different users:
    - A powerful **Command-Line Interface (CLI)** for technical users to test networks and run a local proxy.
    - **Mobile library bindings** to enable the creation of simple, one-click apps for Android and iOS.

## Key Features

- **Core Circumvention Library (`gocircum`)**: A self-contained, headless Go library that provides all core functionality. It can be easily imported into other Go projects.
- **YAML-based Strategy Configuration**: Define and enable different transport protocols (`tcp`, `quic`), TLS libraries (`go-stdlib`, `utls`, `uquic`), and middlewares (like packet fragmentation) in a simple text file.
- **Command-Line Interface (`heybabe-cli`)**: A feature-rich CLI for technical users.
    - `test`: Run all enabled strategies and report on their success and performance.
    - `proxy`: Start a local SOCKS5 proxy using the best available strategy.
- **Automated Best-Strategy Selection**: A built-in "Ranker" module silently tests strategies to find the fastest, most reliable one for the user's current network conditions.
- **Mobile-Ready**: Generates `.aar` and `.xcframework` artifacts for easy integration into Android and iOS applications.
- **Proof-of-Concept Mobile App**: A minimal GUI app demonstrating the one-click connect experience for non-technical users.

## Who is gocircum for?

`gocircum` is designed for two main groups:

1.  **Students, Activists, and Citizens (like "Parisa")**: Individuals in censored regions who need a simple, reliable tool that just works. For them, `gocircum` powers easy-to-use mobile apps with a single "Connect" button.
2.  **Researchers and Developers (like "Kian")**: Technical users who analyze censorship and need a powerful, scriptable tool to probe networks, test new evasion techniques, and build custom circumvention tools.

## Getting Started

### Prerequisites

- Go (latest version recommended)

### Installing the CLI (`heybabe-cli`)

```bash
# Clone the repository
git clone https://github.com/your-repo/gocircum.git
cd gocircum/cmd/heybabe-cli

# Build and install
go install
```

### Using the Library

To use `gocircum` in your own Go project:

```bash
go get -u github.com/your-repo/gocircum
```

```go
package main

import (
	"fmt"
	"github.com/your-repo/gocircum/pkg/core"
)

func main() {
	// Example: Initialize and start the gocircum engine
	// (Note: API is illustrative and subject to change)
	engine, err := core.NewEngine("path/to/strategies.yaml")
	if err != nil {
		panic(err)
	}

	statusChan := engine.Start()

	for status := range statusChan {
		fmt.Println("Engine status:", status)
	}
}
```

## Configuration

The behavior of `gocircum` is controlled by `strategies.yaml`. Here is an example snippet:

```yaml
fingerprints:
  - id: "default_tcp_utls_chrome"
    description: "Default TCP with uTLS Chrome"
    transport:
      protocol: "tcp"
    tls:
      library: "utls"
      client_hello_id: "HelloChrome_Auto"
      min_version: "1.3"
      max_version: "1.3"
      skip_verify: false

  - id: "tcp_fragment_utls_firefox"
    description: "TCP with fragmentation and uTLS Firefox"
    transport:
      protocol: "tcp"
      fragmentation:
        packet_sizes:
          - [10, 20]
          - [30, 50]
        delay_ms: [5, 15]
    tls:
      library: "utls"
      client_hello_id: "HelloFirefox_Auto"
      min_version: "1.3"
      max_version: "1.3"
      skip_verify: false
```

## Platform Support

-   **CLI**: Windows (amd64), macOS (amd64, arm64), Linux (amd64, arm64).
-   **Mobile**: Android API level 21+, iOS 12+.

## Contributing

Contributions are welcome! Whether you're adding new evasion strategies, improving the core library, or fixing bugs, your help is valuable. We aim to foster a strong community to keep the tool effective. Please feel free to open an issue or submit a pull request.

## Out of Scope for MVP

To ensure a focused initial release, the following features are not part of the MVP:

-   A dedicated desktop GUI application.
-   Collection of detailed usage analytics or telemetry.
-   Support for proxy protocols other than SOCKS5.
-   A mechanism for automatically and securely updating the strategy list.

## License

This project is open-source and subject to public audit. (A specific license like MIT or Apache 2.0 will be chosen). 
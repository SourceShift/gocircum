# SecureDNS Package

The `securedns` package provides a secure DNS resolution system that prevents DNS leaks by ensuring all DNS lookups are performed through secure channels (DNS-over-HTTPS).

## Overview

This package addresses critical security vulnerabilities related to DNS leaks in network applications. It ensures that no DNS queries are leaked through the system's default resolver, which is typically unencrypted and can be monitored by network observers.

## Key Features

- **Secure DNS Resolution**: All DNS lookups are performed using DNS-over-HTTPS (DoH).
- **Bootstrap IP System**: Uses pre-resolved IP addresses for DoH providers to avoid the bootstrap paradox.
- **Caching**: Implements efficient caching of DNS results to improve performance.
- **Leak Testing**: Provides tools to verify that no DNS leaks occur.
- **Secure Dialer**: Includes a custom network dialer that ensures all hostname resolution happens through secure channels.
- **HTTP Integration**: Easily integrates with Go's HTTP client to prevent DNS leaks in web requests.

## Usage

### Basic Usage

```go
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/gocircum/gocircum/pkg/securedns"
)

func main() {
    // Create a resolver with default configuration
    resolver, err := securedns.New(nil)
    if err != nil {
        panic(err)
    }
    defer resolver.Close()
    
    // Resolve a hostname
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    ips, err := resolver.LookupIP(ctx, "example.com")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Resolved example.com to: %v\n", ips)
}
```

### Creating a Secure HTTP Client

```go
package main

import (
    "fmt"
    "io/ioutil"
    
    "github.com/gocircum/gocircum/pkg/securedns"
)

func main() {
    // Create a resolver with default configuration
    resolver, err := securedns.New(nil)
    if err != nil {
        panic(err)
    }
    defer resolver.Close()
    
    // Create a secure HTTP client
    client := securedns.NewSecureHTTPClient(resolver)
    
    // Make a request
    resp, err := client.Get("https://example.com")
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()
    
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Response: %s\n", body)
}
```

### Custom Configuration

```go
package main

import (
    "context"
    "fmt"
    "net"
    "time"
    
    "github.com/gocircum/gocircum/pkg/securedns"
)

func main() {
    // Create a custom configuration
    config := &securedns.SecureConfig{
        DoH: &securedns.BootstrapConfig{
            BootstrapIPs: map[string][]net.IP{
                "dns.cloudflare.com": {
                    net.ParseIP("1.1.1.1"),
                    net.ParseIP("1.0.0.1"),
                },
                "dns.google": {
                    net.ParseIP("8.8.8.8"),
                    net.ParseIP("8.8.4.4"),
                },
            },
            TrustedProviders: []string{
                "dns.cloudflare.com",
                "dns.google",
            },
        },
        CacheSize:     1000,
        CacheTTL:      5 * time.Minute,
        Timeout:       5 * time.Second,
        RetryCount:    3,
        BlockFallback: true,
        UserAgent:     "my-secure-app/1.0",
    }
    
    // Create a resolver with the custom configuration
    resolver, err := securedns.New(config)
    if err != nil {
        panic(err)
    }
    defer resolver.Close()
    
    // Use the resolver as before
    ctx := context.Background()
    ips, err := resolver.LookupIP(ctx, "example.com")
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Resolved example.com to: %v\n", ips)
}
```

## Testing for DNS Leaks

The package includes a utility for testing whether DNS leaks occur:

```go
package main

import (
    "fmt"
    
    "github.com/gocircum/gocircum/pkg/securedns"
)

func main() {
    // Create a resolver with default configuration
    resolver, err := securedns.New(nil)
    if err != nil {
        panic(err)
    }
    defer resolver.Close()
    
    // Run a DNS leak test
    result, err := securedns.RunDNSLeakTest(resolver)
    if err != nil {
        panic(err)
    }
    
    if result.LeakDetected {
        fmt.Println("DNS leak detected!")
    } else {
        fmt.Println("No DNS leaks detected.")
    }
}
```

## Command-Line Tool

A command-line tool is provided for testing the secure DNS resolver:

```bash
# Build and run the DNS test tool
./scripts/dnstest.sh --help

# Resolve a hostname
./scripts/dnstest.sh --resolve example.com

# Compare with system DNS
./scripts/dnstest.sh --resolve example.com --compare

# Run a DNS leak test
sudo ./scripts/dnstest.sh --leak-test

# Benchmark the resolver
./scripts/dnstest.sh --benchmark --queries 20
```

## Integration with Existing Code

To integrate the secure DNS resolver with existing code:

1. Replace all direct uses of `net.LookupIP` with the secure resolver.
2. Replace all HTTP clients with secure HTTP clients.
3. Replace all custom dialers with secure dialers.

Example:

```go
// Before
ips, err := net.LookupIP(hostname)

// After
resolver, err := securedns.New(nil)
if err != nil {
    return err
}
defer resolver.Close()

ctx := context.Background()
ips, err := resolver.LookupIP(ctx, hostname)
```

```go
// Before
client := &http.Client{}

// After
resolver, err := securedns.New(nil)
if err != nil {
    return err
}
defer resolver.Close()

client := securedns.NewSecureHTTPClient(resolver)
```

## Security Considerations

- The resolver requires bootstrap IP addresses for DoH providers to avoid the bootstrap paradox.
- The default configuration includes bootstrap IPs for Cloudflare and Google DoH services.
- The resolver will fail securely if all DoH providers are unreachable.
- No fallback to system DNS is provided by default, as this would defeat the purpose of the secure resolver.

## Performance Considerations

- The resolver implements caching to improve performance.
- The first DNS lookup may be slower than subsequent lookups due to connection setup.
- The cache is automatically pruned when it reaches the configured size limit.
- The cache respects TTL values from DNS responses.

## Contributing

Contributions are welcome! Please ensure that any changes maintain the security guarantees of the package. 
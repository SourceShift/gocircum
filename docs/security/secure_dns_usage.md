# Secure DNS Usage Guidelines

## Overview

DNS leak protection is a critical security feature of GoCircum. This document provides guidelines for developers on how to use DNS resolution securely in the codebase.

## Why DNS Leak Protection Matters

DNS queries can reveal information about what applications you are using, what websites you are visiting, and even leak sensitive information. In a security-focused application like GoCircum, it's essential that all DNS resolution happens through secure channels.

## Core Principles

1. **Never use system DNS resolution**: System DNS resolution can bypass our security controls and leak information.
2. **Always use the secure resolver**: The `securedns` package provides secure alternatives for all DNS resolution needs.
3. **Use IP addresses directly when possible**: For known services, hardcode IP addresses or use bootstrap IPs.
4. **Use helper functions**: Always prefer the helper functions over implementing your own DNS resolution.
5. **Handle timeouts appropriately**: Secure DNS resolution may be slower than system DNS.

## Usage Guidelines

### 🚫 DO NOT use these methods (they will cause runtime errors):

```go
// ❌ DO NOT use net package DNS resolution functions
net.LookupIP("example.com")          // BLOCKED - DNS leak
net.LookupHost("example.com")        // BLOCKED - DNS leak
net.LookupAddr("1.1.1.1")            // BLOCKED - DNS leak
net.DefaultResolver.LookupIPAddr(...) // BLOCKED - DNS leak

// ❌ DO NOT create direct dialers that might perform DNS resolution
dialer := &net.Dialer{...}           // BLOCKED - potential DNS leak
dialer.Dial("tcp", "example.com:80") // BLOCKED - DNS leak

// ❌ DO NOT use standard http.Client without secure transport
client := &http.Client{}             // BLOCKED - potential DNS leak
client.Get("https://example.com")    // BLOCKED - DNS leak
```

### ✅ DO use these secure alternatives:

```go
// ✅ Use securedns package for DNS resolution
ips, err := securedns.LookupIP("example.com")
hosts, err := securedns.LookupHost("example.com")

// ✅ Use context-aware versions for timeouts
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
ips, err := securedns.LookupIPContext(ctx, "example.com")

// ✅ Use secure dialer for TCP/UDP connections
conn, err := securedns.DialSecureTCP("example.com:80")

// ✅ Use secure HTTP client
client, err := securedns.GetDefaultSecureHTTPClient()
resp, err := client.Get("https://example.com")

// ✅ Or use the convenience function that panics on initialization error
client := securedns.MustGetDefaultSecureHTTPClient()
```

## Implementing DNS Leak Protection in Your Code

### Creating a Secure Resolver

```go
// Get the default secure resolver (recommended for most cases)
resolver, err := securedns.GetDefaultSecureResolver()
if err != nil {
    // Handle error
}

// Or create a custom resolver with specific options
bootstrapConfig := &securedns.BootstrapConfig{
    BootstrapIPs: map[string][]net.IP{
        "dns.cloudflare.com": {
            net.ParseIP("1.1.1.1"),
            net.ParseIP("1.0.0.1"),
        },
    },
    TrustedProviders: []string{"dns.cloudflare.com"},
}

options := &securedns.Options{
    CacheSize:     1000,
    CacheTTL:      300, // 5 minutes
    Timeout:       5,   // 5 seconds
    RetryCount:    2,
    BlockFallback: true,
}

customResolver, err := securedns.NewDoHResolver(bootstrapConfig, options)
```

### Creating a Secure Dialer

```go
// Get the default secure dialer (recommended for most cases)
dialer, err := securedns.GetDefaultSecureDialer()
if err != nil {
    // Handle error
}
conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")

// Or create a custom dialer with a specific resolver
resolver, _ := securedns.GetDefaultSecureResolver()
factory, _ := securedns.NewSecureDialerFactory(resolver)

customDialer, err := factory.NewTCPDialer(&securedns.DialerConfig{
    Timeout: 10 * time.Second,
})
```

### Creating a Secure HTTP Client

```go
// Get the default secure HTTP client (recommended for most cases)
client, err := securedns.GetDefaultSecureHTTPClient()
if err != nil {
    // Handle error
}

// Or create a custom HTTP client
resolver, _ := securedns.GetDefaultSecureResolver()
factory, _ := securedns.NewSecureDialerFactory(resolver)

transport, err := securedns.CreateSecureTransport(factory, &securedns.TransportConfig{
    // Configure transport options
})

customClient := &http.Client{
    Transport: transport,
    Timeout:   30 * time.Second,
}
```

## Verifying DNS Leak Protection

### Running DNS Leak Tests

GoCircum includes tools to verify that your code isn't leaking DNS queries:

```go
// Run a DNS leak test
resolver, _ := securedns.GetDefaultSecureResolver()
result, err := securedns.RunDNSLeakTest(resolver)
if err != nil {
    // Handle error
}

if result.LeakDetected {
    // DNS leak detected!
    fmt.Println("DNS leak detected:", result.RawOutput)
}
```

### Using the DNS Leak Monitor

The DNS leak monitor is automatically enabled and will detect and block insecure DNS resolution attempts:

```go
// Get the DNS leak monitor
monitor := security.GetDNSLeakMonitor()

// Configure the monitor
security.ConfigureDNSLeakMonitor(&security.DNSLeakMonitorOptions{
    PanicOnLeak:    true,  // Panic when a leak is detected (good for development)
    MaxHistorySize: 1000,  // Keep history of detected leaks
})

// Check if any leaks have been detected
if monitor.HasLeakBeenDetected() {
    history := monitor.GetDetectionHistory()
    for _, leak := range history {
        fmt.Printf("Leak detected from %s: %s\n", leak.Source, leak.Address)
    }
}
```

## CI Integration

Our CI pipeline automatically checks for potential DNS leaks using:

1. Static analysis with the `dnsleaks-linter` tool
2. Runtime tests that verify DNS leak protection is working
3. Integration tests that validate secure DNS resolution

## Common Pitfalls

1. **Third-party libraries**: Be careful when using third-party libraries that might perform their own DNS resolution. Always check and wrap these libraries with secure alternatives.

2. **Custom dialers**: Never create custom dialers without using the `securedns` package.

3. **Hostname vs. IP**: Always check if you're dealing with a hostname (needs secure resolution) or an IP address (can be used directly).

   ```go
   address := "example.com:80"
   host := securedns.ExtractHostname(address)
   
   if securedns.IsIPAddress(host) {
       // Direct connection to IP is safe
       conn, err := net.Dial("tcp", address)
   } else {
       // Need secure DNS resolution
       conn, err := securedns.DialSecureTCP(address)
   }
   ```

4. **Timeouts**: Secure DNS resolution may take longer than system DNS. Always use appropriate timeouts.

5. **Error handling**: Be prepared to handle DNS resolution failures gracefully.

## Reporting DNS Leak Issues

If you discover a potential DNS leak in the codebase:

1. File a high priority issue with the "security" and "dns-leak" labels
2. Include detailed information about where and how the leak is occurring
3. If possible, add a failing test case that demonstrates the leak

## Further Reading

- [Secure DNS Implementation Details](./secure_dns.md)
- [DNS over HTTPS (DoH) Protocol RFC8484](https://tools.ietf.org/html/rfc8484)
- [DNS Security Considerations RFC3833](https://tools.ietf.org/html/rfc3833) 
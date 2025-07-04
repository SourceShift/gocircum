# Secure DNS Usage Guidelines

This document provides guidelines for securely handling DNS resolution in the GoCircum project to prevent DNS leaks that could compromise user privacy and security.

## What is a DNS Leak?

A DNS leak occurs when a DNS query is sent to an untrusted resolver, typically the system's default DNS resolver, instead of using our secure DNS-over-HTTPS (DoH) implementation. These leaks can expose sensitive information about a user's browsing or connection history to ISPs, network administrators, or malicious actors.

## Core Principles

1. **Always use securedns package**: Never use the standard library's `net.LookupIP` or `net.Dialer` directly for hostname resolution.
2. **Strict resolve-then-dial pattern**: Always resolve hostnames using our secure resolver before dialing connections.
3. **No insecure fallbacks**: Never fall back to system DNS if secure resolution fails.
4. **Use provided helpers**: Utilize the helper functions and wrappers provided in the `securedns` package.

## Using the securedns Package

### Basic Hostname Resolution

```go
import "github.com/gocircum/gocircum/pkg/securedns"

// Use the package-level helper (easiest approach)
ips, err := securedns.LookupIP("example.com")
if err != nil {
    // Handle error - NEVER fall back to net.LookupIP
    return err
}

// With context
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
defer cancel()
ips, err := securedns.LookupIPContext(ctx, "example.com")
```

### Making Network Connections

```go
// Use the secure dial context helper
conn, err := securedns.SecureDialContext(ctx, "tcp", "example.com:443")
if err != nil {
    // Handle error - NEVER fall back to standard net.Dialer
    return err
}
defer conn.Close()
```

### Creating HTTP Clients

```go
// Get a secure HTTP client with default settings
client, err := securedns.GetDefaultSecureHTTPClient()
if err != nil {
    // Handle error
    return err
}

// Use the client for HTTP requests
resp, err := client.Get("https://example.com")
```

### Using the SafeWrapper

For more complex scenarios, use the `SafeWrapper` which provides a complete set of secure alternatives:

```go
// Create a safe wrapper with the default secure resolver
wrapper, err := securedns.NewSafeWrapper(nil)
if err != nil {
    return err
}

// Use the wrapper for DNS lookups
ips, err := wrapper.LookupIP("example.com")

// Use the wrapper for dialing
conn, err := wrapper.Dial("tcp", "example.com:443")

// Create an HTTP client with a specific timeout
client, err := wrapper.CreateHTTPClient(30 * time.Second)
```

## Advanced Usage

For advanced use cases where you need full control over the resolver or connection options, you can:

1. Create a custom resolver:

```go
// Configure bootstrap IPs for DoH providers
bootstrapConfig := &securedns.BootstrapConfig{
    BootstrapIPs: map[string][]net.IP{
        "dns.cloudflare.com": {
            net.ParseIP("1.1.1.1"),
            net.ParseIP("1.0.0.1"),
        },
    },
    TrustedProviders: []string{"dns.cloudflare.com"},
}

// Create resolver options
options := &securedns.Options{
    CacheSize: 1000,
    CacheTTL:  300, // 5 minutes
    Timeout:   5,   // 5 seconds
}

// Create the resolver
resolver, err := securedns.NewDoHResolver(bootstrapConfig, options)
if err != nil {
    return err
}

// Use the resolver
ips, err := resolver.LookupIP(ctx, "example.com")
```

2. Create a custom dialer factory:

```go
// Create a dialer factory with your resolver
factory, err := securedns.NewSecureDialerFactory(resolver)
if err != nil {
    return err
}

// Create a TCP dialer with custom configuration
dialer, err := factory.NewTCPDialer(&securedns.DialerConfig{
    Timeout:   30 * time.Second,
    KeepAlive: 30 * time.Second,
})
if err != nil {
    return err
}

// Use the dialer
conn, err := dialer.DialContext(ctx, "tcp", "example.com:443")
```

## DNS Leak Detection and Prevention

The project includes a DNS leak monitor that can detect and prevent attempts to use insecure system DNS resolvers:

```go
// Get the DNS leak monitor
monitor := security.GetDNSLeakMonitor()

// Configure options
security.ConfigureDNSLeakMonitor(&security.DNSLeakMonitorOptions{
    // Enable panic on leak for critical applications
    PanicOnLeak: true,
    
    // Set callback for leak alerts
    AlertCallback: func(detection security.LeakDetection) {
        // Log, alert, or take other action when a leak is detected
    },
})

// Check if leaks have been detected
if monitor.HasLeakBeenDetected() {
    // Take remediation action
    leaks := monitor.GetDetectionHistory()
    for _, leak := range leaks {
        log.Printf("DNS leak detected from %s to %s", leak.Source, leak.Address)
    }
}
```

## Common Mistakes to Avoid

1. ❌ **Never use standard library DNS functions directly**:
   ```go
   // WRONG! This will leak DNS queries to the system resolver
   ips, err := net.LookupIP("example.com")
   ```

2. ❌ **Never create raw Dialers**:
   ```go
   // WRONG! This Dialer will use the system resolver
   dialer := &net.Dialer{Timeout: 5 * time.Second}
   ```

3. ❌ **Never use the default HTTP client**:
   ```go
   // WRONG! Default HTTP client uses system resolver
   resp, err := http.Get("https://example.com")
   ```

4. ❌ **Never add fallbacks to system DNS**:
   ```go
   // WRONG! Falling back to system DNS leaks queries
   ips, err := secureResolver.LookupIP(ctx, hostname)
   if err != nil {
       // WRONG! This fallback leaks DNS
       ips, err = net.LookupIP(hostname)
   }
   ```

## Testing for DNS Leaks

The `securedns` package includes tools to test for DNS leaks:

```go
// Run a DNS leak test
result, err := securedns.RunDNSLeakTest(resolver)
if err != nil {
    return err
}

if result.LeakDetected {
    log.Println("DNS leak detected!")
    log.Printf("System DNS servers: %v", result.SystemDNS)
    log.Printf("Raw output: %s", result.RawOutput)
}
```

## Additional Resources

- See `pkg/securedns/README.md` for more details on the secure DNS implementation
- See `core/security/dns_safeguards.go` for details on the runtime leak prevention mechanisms
- Run `make lint-dnsleaks` to check your code for potential DNS leaks before committing 
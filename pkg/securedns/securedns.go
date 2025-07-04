package securedns

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"
)

// DefaultTimeout is the default timeout for DNS queries.
const DefaultTimeout = 5 * time.Second

// DefaultCacheTTL is the default TTL for cached DNS entries.
const DefaultCacheTTL = 5 * time.Minute

// DefaultCacheSize is the default size of the DNS cache.
const DefaultCacheSize = 1000

// SecureConfig contains all configuration for the secure DNS system.
type SecureConfig struct {
	// DoH configuration
	DoH *BootstrapConfig

	// Optional configurations
	CacheSize     int
	CacheTTL      time.Duration
	Timeout       time.Duration
	RetryCount    int
	BlockFallback bool
	UserAgent     string
}

// DefaultConfig returns a default secure configuration using
// Cloudflare and Google's DoH services.
func DefaultConfig() *SecureConfig {
	return &SecureConfig{
		DoH: &BootstrapConfig{
			BootstrapIPs: map[string][]net.IP{
				"dns.cloudflare.com": {
					net.ParseIP("1.1.1.1"),
					net.ParseIP("1.0.0.1"),
					net.ParseIP("2606:4700:4700::1111"),
					net.ParseIP("2606:4700:4700::1001"),
				},
				"dns.google": {
					net.ParseIP("8.8.8.8"),
					net.ParseIP("8.8.4.4"),
					net.ParseIP("2001:4860:4860::8888"),
					net.ParseIP("2001:4860:4860::8844"),
				},
			},
			TrustedProviders: []string{
				"dns.cloudflare.com",
				"dns.google",
			},
			RefreshInterval: 86400, // 24 hours in seconds
		},
		CacheSize:     DefaultCacheSize,
		CacheTTL:      DefaultCacheTTL,
		Timeout:       DefaultTimeout,
		RetryCount:    3,
		BlockFallback: true,
		UserAgent:     "gocircum-securedns/1.0",
	}
}

// New creates a new secure DNS resolver with the provided configuration.
// If config is nil, the default configuration will be used.
func New(config *SecureConfig) (Resolver, error) {
	if config == nil {
		config = DefaultConfig()
	}

	options := &Options{
		CacheSize:                config.CacheSize,
		CacheTTL:                 int(config.CacheTTL.Seconds()), // Convert to seconds
		Timeout:                  int(config.Timeout.Seconds()),
		RetryCount:               config.RetryCount,
		BlockFallback:            config.BlockFallback,
		UserAgent:                config.UserAgent,
		VerifyBootstrapIntegrity: true,
	}

	return NewDoHResolver(config.DoH, options)
}

// NewSecureTransport creates an HTTP transport that uses secure DNS resolution.
// This can be used with HTTP clients to prevent DNS leaks.
func NewSecureTransport(resolver Resolver) http.RoundTripper {
	dialer := NewSecureDialerWithResolver(resolver)

	return &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		// Disable proxy to prevent leaks
		Proxy: nil,
	}
}

// NewSecureHTTPClient creates an HTTP client that uses secure DNS resolution.
func NewSecureHTTPClient(resolver Resolver) *http.Client {
	return &http.Client{
		Transport: NewSecureTransport(resolver),
		Timeout:   30 * time.Second,
	}
}

// ResolveIP resolves a hostname to its IPs using the secure resolver.
// This is a convenience function that creates a resolver with the default config.
func ResolveIP(hostname string) ([]net.IP, error) {
	resolver, err := New(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure resolver: %w", err)
	}
	defer func() {
		if closeErr := resolver.Close(); closeErr != nil {
			// We can't return the error here, so we just log it
			log.Printf("Error closing resolver: %v", closeErr)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeout)
	defer cancel()

	return resolver.LookupIP(ctx, hostname)
}

// NewSecureDialerWithResolver creates a SecureDialer that uses the given resolver.
// This returns the interface to avoid conflicts with the dohresolver implementation.
func NewSecureDialerWithResolver(resolver Resolver) SecureDialer {
	// Use type assertion to check if resolver already implements SecureDialer
	if dialer, ok := resolver.(SecureDialer); ok {
		return dialer
	}

	// Otherwise, create a new secure dialer wrapper
	return newSecureDialerWrapper(resolver)
}

// secureDialerWrapper is a wrapper around a resolver that implements SecureDialer.
// This is distinct from the secureDialer in dohresolver.go
type secureDialerWrapper struct {
	resolver Resolver
}

// newSecureDialerWrapper creates a new secureDialerWrapper.
func newSecureDialerWrapper(resolver Resolver) *secureDialerWrapper {
	return &secureDialerWrapper{resolver: resolver}
}

// DialContext implements the SecureDialer interface.
func (d *secureDialerWrapper) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %w", addr, err)
	}

	// Check if host is already an IP
	if net.ParseIP(host) != nil {
		// Direct dial if the host is already an IP
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}

	// Resolve the hostname using our secure resolver
	ips, err := d.resolver.LookupIP(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("secure DNS resolution failed for %s: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for host: %s", host)
	}

	// Try each IP until one succeeds
	var lastErr error
	for _, ip := range ips {
		targetAddr := net.JoinHostPort(ip.String(), port)
		conn, err := (&net.Dialer{}).DialContext(ctx, network, targetAddr)
		if err != nil {
			lastErr = err
			continue
		}
		return conn, nil
	}

	return nil, fmt.Errorf("failed to connect to %s: %v", addr, lastErr)
}

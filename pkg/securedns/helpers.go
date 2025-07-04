package securedns

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gocircum/gocircum/core/security"
)

// Helper functions to make secure DNS resolution easy for developers
// These functions should be the primary way developers interact with DNS resolution
// throughout the codebase

var (
	// defaultResolver is the global default secure resolver
	defaultResolver Resolver

	// defaultHTTPClient is the global default secure HTTP client
	defaultHTTPClient *http.Client
)

// GetDefaultSecureResolver returns the default secure resolver.
// It initializes the resolver on the first call.
func GetDefaultSecureResolver() (Resolver, error) {
	if defaultResolver != nil {
		return defaultResolver, nil
	}

	bootstrapConfig := &BootstrapConfig{
		// Hardcoded bootstrap IP addresses for DNS-over-HTTPS providers
		BootstrapIPs: map[string][]net.IP{
			"dns.cloudflare.com": {
				net.ParseIP("1.1.1.1"),
				net.ParseIP("1.0.0.1"),
			},
			"dns.google": {
				net.ParseIP("8.8.8.8"),
				net.ParseIP("8.8.4.4"),
			},
			"dns.quad9.net": {
				net.ParseIP("9.9.9.9"),
				net.ParseIP("149.112.112.112"),
			},
		},
		TrustedProviders: []string{
			"dns.cloudflare.com",
			"dns.google",
			"dns.quad9.net",
		},
	}

	options := &Options{
		CacheSize:     1000,
		CacheTTL:      300, // 5 minutes
		Timeout:       5,   // 5 seconds
		RetryCount:    2,
		BlockFallback: true, // Never fall back to insecure DNS
		UserAgent:     "gocircum-securedns/1.0",
	}

	resolver, err := NewDoHResolver(bootstrapConfig, options)
	if err != nil {
		return nil, fmt.Errorf("failed to create default secure resolver: %w", err)
	}

	// Install hooks with security monitor
	monitor := security.GetDNSLeakMonitor()
	if monitor != nil {
		security.ConfigureDNSLeakMonitor(&security.DNSLeakMonitorOptions{
			PanicOnLeak:    true, // This ensures we catch DNS leaks early in development
			MaxHistorySize: 1000, // Keep a larger history for debugging
			AlertCallback:  nil,  // No custom alert for now
		})
	}

	defaultResolver = resolver
	return defaultResolver, nil
}

// LookupIP is a secure replacement for net.LookupIP
// This is the preferred method for DNS resolution throughout the codebase
func LookupIP(hostname string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return LookupIPWithContext(ctx, hostname)
}

// LookupIPWithContext is a context-aware secure replacement for net.LookupIP
func LookupIPWithContext(ctx context.Context, hostname string) ([]net.IP, error) {
	resolver, err := GetDefaultSecureResolver()
	if err != nil {
		return nil, fmt.Errorf("failed to get secure resolver: %w", err)
	}

	return resolver.LookupIP(ctx, hostname)
}

// LookupHost is a secure replacement for net.LookupHost
func LookupHost(hostname string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return LookupHostWithContext(ctx, hostname)
}

// LookupHostWithContext is a context-aware secure replacement for net.LookupHost
func LookupHostWithContext(ctx context.Context, hostname string) ([]string, error) {
	resolver, err := GetDefaultSecureResolver()
	if err != nil {
		return nil, fmt.Errorf("failed to get secure resolver: %w", err)
	}

	ips, err := resolver.LookupIP(ctx, hostname)
	if err != nil {
		return nil, err
	}

	var hosts []string
	for _, ip := range ips {
		hosts = append(hosts, ip.String())
	}

	return hosts, nil
}

// LookupAddr is a secure replacement for net.LookupAddr (reverse DNS lookup)
// Note: This is not currently implemented in the base Resolver interface
func LookupAddr(addr string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return LookupAddrWithContext(ctx, addr)
}

// LookupAddrWithContext is a context-aware secure replacement for net.LookupAddr
// Note: This is not currently implemented in the base Resolver interface
func LookupAddrWithContext(ctx context.Context, addr string) ([]string, error) {
	// This functionality is not currently implemented in the base Resolver
	// Return a meaningful error instead
	return nil, fmt.Errorf("reverse DNS lookup not implemented in the secure resolver")
}

// GetDefaultSecureDialer returns a preconfigured secure dialer ready to use
func GetDefaultSecureDialer() (SecureDialer, error) {
	resolver, err := GetDefaultSecureResolver()
	if err != nil {
		return nil, fmt.Errorf("failed to get secure resolver: %w", err)
	}

	// Create a SecureDialerFactory with the default resolver
	factory, err := NewSecureDialerFactory(resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure dialer factory: %w", err)
	}

	// Create a TCP dialer with default options
	dialer, err := factory.NewTCPDialer(&DialerConfig{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create secure dialer: %w", err)
	}

	return dialer, nil
}

// DialSecureTCP is a secure replacement for net.Dial with "tcp" network
func DialSecureTCP(address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return DialSecureTCPWithContext(ctx, address)
}

// DialSecureTCPWithContext is a context-aware secure replacement for net.DialContext with "tcp" network
func DialSecureTCPWithContext(ctx context.Context, address string) (net.Conn, error) {
	dialer, err := GetDefaultSecureDialer()
	if err != nil {
		return nil, fmt.Errorf("failed to get secure dialer: %w", err)
	}

	return dialer.DialContext(ctx, "tcp", address)
}

// GetDefaultSecureUDPDialer returns a preconfigured secure UDP dialer ready to use
func GetDefaultSecureUDPDialer() (SecureDialer, error) {
	resolver, err := GetDefaultSecureResolver()
	if err != nil {
		return nil, fmt.Errorf("failed to get secure resolver: %w", err)
	}

	// Create a SecureDialerFactory with the default resolver
	factory, err := NewSecureDialerFactory(resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure dialer factory: %w", err)
	}

	// Create a UDP dialer with default options
	dialer, err := factory.NewUDPDialer(&DialerConfig{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create secure UDP dialer: %w", err)
	}

	return dialer, nil
}

// DialSecureUDP is a secure replacement for net.Dial with "udp" network
func DialSecureUDP(address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return DialSecureUDPWithContext(ctx, address)
}

// DialSecureUDPWithContext is a context-aware secure replacement for net.DialContext with "udp" network
func DialSecureUDPWithContext(ctx context.Context, address string) (net.Conn, error) {
	dialer, err := GetDefaultSecureUDPDialer()
	if err != nil {
		return nil, fmt.Errorf("failed to get secure UDP dialer: %w", err)
	}

	return dialer.DialContext(ctx, "udp", address)
}

// GetDefaultSecureHTTPClient returns a preconfigured HTTP client that uses secure DNS resolution
func GetDefaultSecureHTTPClient() (*http.Client, error) {
	if defaultHTTPClient != nil {
		return defaultHTTPClient, nil
	}

	resolver, err := GetDefaultSecureResolver()
	if err != nil {
		return nil, err
	}

	// Create a SecureDialerFactory with the default resolver
	factory, err := NewSecureDialerFactory(resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure dialer factory: %w", err)
	}

	// Create and configure transport
	transportConfig := &TransportConfig{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}

	// Create the transport
	transport, err := CreateSecureTransport(factory, transportConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure transport: %w", err)
	}

	// Create the client with the transport
	client := &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}

	defaultHTTPClient = client
	return client, nil
}

// MustGetDefaultSecureHTTPClient returns a preconfigured HTTP client and panics if there's an error
func MustGetDefaultSecureHTTPClient() *http.Client {
	client, err := GetDefaultSecureHTTPClient()
	if err != nil {
		panic(fmt.Sprintf("failed to create secure HTTP client: %v", err))
	}
	return client
}

// IsIPAddress checks if a hostname is an IP address
func IsIPAddress(hostname string) bool {
	return net.ParseIP(hostname) != nil
}

// ExtractHostname extracts the hostname from a host:port address
func ExtractHostname(address string) string {
	hostname, _, err := net.SplitHostPort(address)
	if err != nil {
		// If SplitHostPort fails, assume the address is just a hostname
		return address
	}
	return hostname
}

// LookupIPContext is a context-aware secure replacement for net.LookupIPAddr
func LookupIPContext(ctx context.Context, hostname string) ([]net.IP, error) {
	resolver, err := GetDefaultSecureResolver()
	if err != nil {
		return nil, fmt.Errorf("failed to get secure resolver: %w", err)
	}

	return resolver.LookupIP(ctx, hostname)
}

// SecureDialContext is a secure replacement for net.Dialer.DialContext
func SecureDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer, err := GetDefaultSecureDialer()
	if err != nil {
		return nil, fmt.Errorf("failed to get secure dialer: %w", err)
	}

	return dialer.DialContext(ctx, network, address)
}

// SafeWrapper provides a convenience wrapper around common secure DNS operations
type SafeWrapper struct {
	resolver Resolver
	factory  SecureDialerFactory
}

// NewSafeWrapper creates a new SafeWrapper with the default resolver and dialer factory
func NewSafeWrapper() (*SafeWrapper, error) {
	resolver, err := GetDefaultSecureResolver()
	if err != nil {
		return nil, fmt.Errorf("failed to get secure resolver: %w", err)
	}

	factory, err := NewSecureDialerFactory(resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure dialer factory: %w", err)
	}

	return &SafeWrapper{
		resolver: resolver,
		factory:  factory,
	}, nil
}

// Dial creates a secure connection to the given address
func (s *SafeWrapper) Dial(network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.DialContext(ctx, network, address)
}

// DialContext creates a secure connection to the given address with context
func (s *SafeWrapper) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	dialer, err := s.factory.NewDialer(&DialerConfig{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, address)
}

// LookupIP performs a secure DNS lookup for the given hostname
func (s *SafeWrapper) LookupIP(hostname string) ([]net.IP, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.LookupIPContext(ctx, hostname)
}

// LookupIPContext performs a secure DNS lookup for the given hostname with context
func (s *SafeWrapper) LookupIPContext(ctx context.Context, hostname string) ([]net.IP, error) {
	return s.resolver.LookupIP(ctx, hostname)
}

// CreateHTTPClient creates a secure HTTP client
func (s *SafeWrapper) CreateHTTPClient(timeout time.Duration) (*http.Client, error) {
	transport, err := CreateSecureTransport(s.factory, &TransportConfig{
		IdleConnTimeout: 90 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}, nil
}

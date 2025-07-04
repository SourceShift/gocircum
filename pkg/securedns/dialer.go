// Package securedns provides a DNS resolution system that prevents DNS leaks
// by ensuring all DNS lookups are performed through secure channels (DoH).
package securedns

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"
)

// SecureDialerFactory is responsible for creating secure dialers that
// ensure all DNS resolutions happen through secure channels to prevent DNS leaks.
type SecureDialerFactory interface {
	// NewDialer creates a new secure dialer with the specified configuration.
	NewDialer(config *DialerConfig) (SecureDialer, error)

	// NewTCPDialer creates a new secure dialer specifically for TCP connections.
	NewTCPDialer(config *DialerConfig) (SecureDialer, error)

	// NewUDPDialer creates a new secure dialer specifically for UDP connections.
	NewUDPDialer(config *DialerConfig) (SecureDialer, error)

	// Close releases any resources used by the factory.
	Close() error
}

// DialerConfig contains configuration options for secure dialers.
type DialerConfig struct {
	// Timeout is the maximum amount of time a dial will wait for a connection to complete.
	Timeout time.Duration

	// KeepAlive specifies the keep-alive period for an active network connection.
	// If zero, keep-alives are not enabled.
	KeepAlive time.Duration

	// FallbackDelay is the duration to wait before falling back to a secondary address.
	// If zero, no fallback is enabled.
	FallbackDelay time.Duration

	// LocalAddr is the local address to use when dialing an address.
	// If nil, a local address is automatically chosen.
	LocalAddr net.Addr
}

// DefaultSecureDialerFactory implements the SecureDialerFactory interface using
// the provided Resolver for secure DNS resolution.
type DefaultSecureDialerFactory struct {
	resolver Resolver
}

// NewSecureDialerFactory creates a new DefaultSecureDialerFactory with the provided resolver.
func NewSecureDialerFactory(resolver Resolver) (SecureDialerFactory, error) {
	if resolver == nil {
		return nil, fmt.Errorf("resolver cannot be nil")
	}

	return &DefaultSecureDialerFactory{
		resolver: resolver,
	}, nil
}

// NewDialer creates a new secure dialer with the specified configuration.
func (f *DefaultSecureDialerFactory) NewDialer(config *DialerConfig) (SecureDialer, error) {
	return f.NewTCPDialer(config)
}

// NewTCPDialer creates a new secure dialer specifically for TCP connections.
func (f *DefaultSecureDialerFactory) NewTCPDialer(config *DialerConfig) (SecureDialer, error) {
	if config == nil {
		config = &DialerConfig{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
	}

	return &defaultSecureDialer{
		resolver:      f.resolver,
		network:       "tcp",
		timeout:       config.Timeout,
		keepAlive:     config.KeepAlive,
		fallbackDelay: config.FallbackDelay,
		localAddr:     config.LocalAddr,
	}, nil
}

// NewUDPDialer creates a new secure dialer specifically for UDP connections.
func (f *DefaultSecureDialerFactory) NewUDPDialer(config *DialerConfig) (SecureDialer, error) {
	if config == nil {
		config = &DialerConfig{
			Timeout: 30 * time.Second,
		}
	}

	return &defaultSecureDialer{
		resolver:      f.resolver,
		network:       "udp",
		timeout:       config.Timeout,
		fallbackDelay: config.FallbackDelay,
		localAddr:     config.LocalAddr,
	}, nil
}

// Close releases any resources used by the factory.
func (f *DefaultSecureDialerFactory) Close() error {
	return nil
}

// defaultSecureDialer implements the SecureDialer interface.
type defaultSecureDialer struct {
	resolver      Resolver
	network       string
	timeout       time.Duration
	keepAlive     time.Duration
	fallbackDelay time.Duration
	localAddr     net.Addr
}

// DialContext connects to the address on the named network using the provided context.
// The address parameter should be a hostname:port or IP:port combination.
// If a hostname is provided, it will be resolved using secure DNS before establishing the connection.
func (d *defaultSecureDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// If the network doesn't match what this dialer was configured for, return an error
	if network != d.network && network != d.network+"4" && network != d.network+"6" {
		return nil, fmt.Errorf("network mismatch: dialer is configured for %s, but %s was requested", d.network, network)
	}

	// Parse the address into host and port
	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %w", err)
	}

	// Parse the port
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}

	// If the host is already an IP address, dial directly
	if net.ParseIP(host) != nil {
		return d.dialIP(ctx, network, host, port)
	}

	// Resolve the hostname using our secure resolver
	ips, err := d.resolver.LookupIPWithCache(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("secure DNS resolution failed for %s: %w", host, err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", host)
	}

	// Try each IP until one works or we run out
	var firstErr error
	for _, ip := range ips {
		conn, err := d.dialIP(ctx, network, ip.String(), port)
		if err == nil {
			return conn, nil
		}

		if firstErr == nil {
			firstErr = err
		}
	}

	return nil, fmt.Errorf("failed to connect to any resolved IP for %s: %w", host, firstErr)
}

// dialIP dials a connection to the specified IP address and port.
func (d *defaultSecureDialer) dialIP(ctx context.Context, network string, ip string, port int) (net.Conn, error) {
	// Create a dialer with our configuration
	dialer := &net.Dialer{
		Timeout:       d.timeout,
		KeepAlive:     d.keepAlive,
		FallbackDelay: d.fallbackDelay,
		LocalAddr:     d.localAddr,
	}

	// Dial the connection
	address := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s: %w", address, err)
	}

	return conn, nil
}

// Package securedns provides a DNS resolution system that prevents DNS leaks
// by ensuring all DNS lookups are performed through secure channels (DoH).
package securedns

import (
	"context"
	"net"
)

//go:generate mockgen -package=mocks -destination=../../mocks/mock_resolver.go github.com/gocircum/gocircum/pkg/securedns Resolver

// Resolver defines the interface for secure DNS resolution.
// It ensures that no DNS queries are leaked through system DNS.
type Resolver interface {
	// LookupIP looks up the given host using only secure DNS resolution methods.
	// It explicitly avoids using the system's default DNS resolver.
	LookupIP(ctx context.Context, host string) ([]net.IP, error)

	// LookupIPWithCache looks up the given host with secure DNS resolution,
	// but checks and updates an internal cache first.
	LookupIPWithCache(ctx context.Context, host string) ([]net.IP, error)

	// PreloadCache preloads the IP address cache with the provided hostname->IP mappings.
	// This is particularly useful for bootstrap IPs of DoH providers.
	PreloadCache(entries map[string][]net.IP)

	// VerifyNoLeaks performs verification checks to ensure that DNS lookups
	// cannot leak through system DNS.
	VerifyNoLeaks(ctx context.Context) error

	// Close releases any resources used by the resolver.
	Close() error
}

// BootstrapConfig contains the configuration for bootstrapping the secure DNS resolver.
type BootstrapConfig struct {
	// BootstrapIPs is a map of hostname to IP addresses for DoH providers.
	// These IPs are used to establish the initial secure connection without
	// requiring a DNS lookup through the system resolver.
	BootstrapIPs map[string][]net.IP

	// FallbackIPs provides additional IP addresses to try if the primary
	// bootstrap IPs are unreachable.
	FallbackIPs map[string][]net.IP

	// TrustedProviders is the list of trusted DoH provider hostnames.
	TrustedProviders []string

	// RefreshInterval is the interval at which bootstrap IPs are refreshed
	// through secure channels. Set to 0 to disable automatic refreshing.
	RefreshInterval int
}

// SecureDialer defines an interface for creating network connections that
// ensure all hostname resolution happens through secure DNS channels.
type SecureDialer interface {
	// DialContext connects to the address on the named network using the provided context.
	// The address parameter should be a hostname:port or IP:port combination.
	// If a hostname is provided, it will be resolved using secure DNS before establishing the connection.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// Options contains configuration options for the resolver.
type Options struct {
	// CacheSize is the maximum number of entries to keep in the DNS cache.
	CacheSize int

	// CacheTTL is the time-to-live for cached DNS entries in seconds.
	CacheTTL int

	// Timeout is the timeout for DNS lookups in seconds.
	Timeout int

	// RetryCount is the number of times to retry a failed DNS lookup.
	RetryCount int

	// VerifyBootstrapIntegrity enables cryptographic verification of
	// bootstrap responses to detect tampering.
	VerifyBootstrapIntegrity bool

	// BlockFallback determines if the resolver should fail rather than
	// fall back to less secure methods.
	BlockFallback bool

	// UserAgent is the User-Agent header to use for DoH requests.
	UserAgent string
}

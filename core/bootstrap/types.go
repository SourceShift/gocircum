package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
)

// BootstrapProvider defines the interface for different bootstrap discovery mechanisms
type BootstrapProvider interface {
	// Name returns the name of the bootstrap provider
	Name() string

	// Discover returns a list of bootstrap addresses (IP:port) using this provider's discovery method
	Discover(ctx context.Context) ([]string, error)

	// Priority returns the priority of this provider (higher values are tried first)
	Priority() int
}

// BootstrapResult represents the result of a bootstrap discovery attempt
type BootstrapResult struct {
	// Provider is the name of the provider that discovered these addresses
	Provider string

	// Addresses is a list of bootstrap addresses in the format "ip:port"
	Addresses []string

	// Timestamp is when these addresses were discovered
	Timestamp time.Time

	// TTL is how long these addresses are valid for
	TTL time.Duration
}

// HealthCheckOptions configures how bootstrap addresses are health-checked
type HealthCheckOptions struct {
	// Enabled determines whether health checking is performed
	Enabled bool

	// Timeout is the maximum time to wait for a health check
	Timeout time.Duration

	// Concurrency is the maximum number of concurrent health checks
	Concurrency int

	// RequiredSuccessRate is the percentage of addresses that must pass health checks
	RequiredSuccessRate float64
}

// BootstrapConfig defines the configuration for bootstrap discovery
type BootstrapConfig struct {
	// Providers is a list of bootstrap provider configurations
	Providers []ProviderConfig `yaml:"providers"`

	// HealthCheck configures how bootstrap addresses are validated
	HealthCheck HealthCheckOptions `yaml:"health_check"`

	// CacheTTL is how long discovered addresses are cached
	CacheTTL time.Duration `yaml:"cache_ttl"`

	// FallbackAddresses is a list of addresses to use if all discovery methods fail
	FallbackAddresses []string `yaml:"fallback_addresses"`
}

// ProviderConfig contains configuration for a specific bootstrap provider
type ProviderConfig struct {
	// Type specifies the provider type (e.g., "domain_fronted", "doh", "well_known")
	Type string `yaml:"type"`

	// Enabled determines whether this provider is active
	Enabled bool `yaml:"enabled"`

	// Priority determines the order in which providers are tried (higher = sooner)
	Priority int `yaml:"priority"`

	// Config contains provider-specific configuration as a map
	Config map[string]interface{} `yaml:"config"`
}

// DoHProviderConfig contains configuration for DNS-over-HTTPS bootstrap providers
type DoHProviderConfig struct {
	// Providers is a list of DoH service providers to use
	Providers []string `yaml:"providers"`

	// URLs is a mapping of provider names to their DoH endpoints
	URLs map[string]string `yaml:"urls"`

	// ServerNames is a mapping of provider names to their SNI values
	ServerNames map[string]string `yaml:"server_names"`

	// QueryTimeout is the maximum time to wait for a DoH query
	QueryTimeout time.Duration `yaml:"query_timeout"`

	// MaxRetries is the number of retries for failed queries
	MaxRetries int `yaml:"max_retries"`

	// Hardened: Multi-channel discovery configuration
	DiscoveryChannels      DiscoveryConfig  `yaml:"discovery_channels"`
	DGAConfig              DGAConfiguration `yaml:"dga_config"`
	SteganographyEndpoints []string         `yaml:"steganography_endpoints"`
}

// DiscoveryConfig contains configuration for decentralized bootstrap discovery
type DiscoveryConfig struct {
	SocialMediaChannels  []SocialChannel `yaml:"social_channels"`
	BlockchainNetworks   []string        `yaml:"blockchain_networks"`
	PeerDiscoveryEnabled bool            `yaml:"peer_discovery"`
}

// SocialChannel represents a social media source for bootstrap discovery
type SocialChannel struct {
	Platform   string `yaml:"platform"`
	Identifier string `yaml:"identifier"`
	Pattern    string `yaml:"pattern"`
}

// DGAConfiguration contains settings for domain generation algorithms
type DGAConfiguration struct {
	Algorithm         string   `yaml:"algorithm"`
	SeedRotationHours int      `yaml:"seed_rotation_hours"`
	TLDs              []string `yaml:"valid_tlds"`
	ClientSecret      []byte   `yaml:"client_secret"`
}

// DomainFrontingConfig contains configuration for domain fronting bootstrap discovery
type DomainFrontingConfig struct {
	// FrontDomains is a list of domains to use for domain fronting
	FrontDomains []string `yaml:"front_domains"`

	// TargetDomains is a list of actual bootstrap service domains
	TargetDomains []string `yaml:"target_domains"`

	// FrontCDNs is a mapping of CDN names to their front domains
	FrontCDNs map[string][]string `yaml:"front_cdns"`

	// RotationInterval is how often to rotate through front domains
	RotationInterval time.Duration `yaml:"rotation_interval"`

	// ConnectTimeout is the timeout for connection attempts
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// WellKnownConfig contains configuration for well-known endpoints discovery
type WellKnownConfig struct {
	// Endpoints is a list of well-known URLs to query for bootstrap information
	Endpoints []string `yaml:"endpoints"`

	// QueryTimeout is the maximum time to wait for endpoint queries
	QueryTimeout time.Duration `yaml:"query_timeout"`

	// ResponseFormat specifies the expected format of responses (json, text)
	ResponseFormat string `yaml:"response_format"`

	// AuthToken is an optional authentication token to include in requests
	AuthToken string `yaml:"auth_token,omitempty"`
}

// IPPoolConfig contains configuration for IP pool management
type IPPoolConfig struct {
	// InitialSize is the target number of IPs to maintain in the pool
	InitialSize int `yaml:"initial_size"`

	// MaxSize is the maximum number of IPs to store in the pool
	MaxSize int `yaml:"max_size"`

	// MinSize is the minimum number of IPs before triggering discovery
	MinSize int `yaml:"min_size"`

	// RefreshInterval is how often to check and refresh the pool
	RefreshInterval time.Duration `yaml:"refresh_interval"`

	// PersistPath is the file path to store discovered IPs between runs
	PersistPath string `yaml:"persist_path,omitempty"`
}

// DiscoveryResult encapsulates the results of a bootstrap discovery operation
type DiscoveryResult struct {
	// Addresses is the list of discovered addresses
	Addresses []string

	// Source is the provider that discovered these addresses
	Source string

	// Error is non-nil if the discovery attempt failed
	Error error
}

// ConnectParams defines parameters for connecting to a bootstrap address
type ConnectParams struct {
	// Addr is the address to connect to
	Addr string

	// Timeout is the maximum time to wait for the connection
	Timeout time.Duration

	// Context is the context for the connection
	Context context.Context

	// ServerName is the TLS server name for the connection
	ServerName string

	// Obfuscated indicates whether the connection should be obfuscated
	Obfuscated bool
}

// Logger is an alias for the project's Logger interface
type Logger = logging.Logger

// IPPool manages a collection of bootstrap IP addresses
type IPPool struct {
	addresses       map[string]time.Time
	mutex           *sync.RWMutex
	maxSize         int
	minSize         int
	refreshInterval time.Duration
	persistPath     string
	logger          Logger
	lastUpdate      time.Time
}

// AddAddresses adds multiple addresses to the IP pool
func (p *IPPool) AddAddresses(addresses []string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	now := time.Now()
	for _, addr := range addresses {
		if len(p.addresses) < p.maxSize {
			p.addresses[addr] = now
		}
	}
	p.lastUpdate = now
}

// GetAddresses returns all addresses currently in the pool
func (p *IPPool) GetAddresses() []string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	addresses := make([]string, 0, len(p.addresses))
	for addr := range p.addresses {
		addresses = append(addresses, addr)
	}
	return addresses
}

// NeedsRefresh checks if the pool needs to be refreshed
func (p *IPPool) NeedsRefresh() bool {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	if len(p.addresses) < p.minSize {
		return true
	}
	
	return time.Since(p.lastUpdate) > p.refreshInterval
}

// SaveToFile saves the IP pool to disk
func (p *IPPool) SaveToFile() error {
	if p.persistPath == "" {
		return nil // No persistence configured
	}
	
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	
	// Create a simple JSON structure to save
	data := struct {
		Addresses  map[string]time.Time `json:"addresses"`
		LastUpdate time.Time            `json:"last_update"`
	}{
		Addresses:  p.addresses,
		LastUpdate: p.lastUpdate,
	}
	
	jsonData, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal IP pool data: %w", err)
	}
	
	return os.WriteFile(p.persistPath, jsonData, 0600)
}

// LoadFromFile loads the IP pool from disk
func (p *IPPool) LoadFromFile() error {
	if p.persistPath == "" {
		return nil // No persistence configured
	}
	
	jsonData, err := os.ReadFile(p.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist yet, that's okay
		}
		return fmt.Errorf("failed to read IP pool file: %w", err)
	}
	
	var data struct {
		Addresses  map[string]time.Time `json:"addresses"`
		LastUpdate time.Time            `json:"last_update"`
	}
	
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return fmt.Errorf("failed to unmarshal IP pool data: %w", err)
	}
	
	p.mutex.Lock()
	defer p.mutex.Unlock()
	
	p.addresses = data.Addresses
	if p.addresses == nil {
		p.addresses = make(map[string]time.Time)
	}
	p.lastUpdate = data.LastUpdate
	
	return nil
}

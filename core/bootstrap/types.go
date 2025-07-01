package bootstrap

import (
	"context"
	"crypto/rand"
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

// EntropySource defines the interface for sources of cryptographic entropy
type EntropySource interface {
	// Name returns the name of the entropy source
	Name() string

	// Gather returns entropy data from this source
	Gather(ctx context.Context) ([]byte, error)

	// Quality returns an estimate of the entropy quality (0.0-1.0)
	Quality() float64
}

// EntropyBundle contains entropy from multiple sources for secure domain generation
type EntropyBundle struct {
	// Sources is a map of entropy source names to their entropy data
	Sources map[string][]byte

	// Timestamp is when this entropy bundle was collected
	Timestamp time.Time

	// QualityScore is the aggregate quality of the entropy (0.0-1.0)
	QualityScore float64
}

// NewEntropyBundle creates a new empty entropy bundle
func NewEntropyBundle() *EntropyBundle {
	return &EntropyBundle{
		Sources:   make(map[string][]byte),
		Timestamp: time.Now(),
	}
}

// AddSource adds entropy from a named source to the bundle
func (eb *EntropyBundle) AddSource(name string, data []byte, quality float64) {
	eb.Sources[name] = data
	// Recalculate the aggregate quality score
	var totalQuality float64
	for range eb.Sources {
		totalQuality += quality
	}
	eb.QualityScore = totalQuality / float64(len(eb.Sources))
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

	// DiscoveryMethod indicates how these addresses were discovered
	DiscoveryMethod string
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

	// EntropyConfig configures the entropy sources for domain generation
	EntropyConfig EntropyConfig `yaml:"entropy_config"`

	// DynamicDiscoveryConfig configures dynamic discovery mechanisms
	DynamicDiscoveryConfig DynamicDiscoveryConfig `yaml:"dynamic_discovery"`

	// SECURITY: FallbackAddresses is removed to eliminate static bootstrap points
	// All bootstrap addresses must be dynamically discovered
}

// EntropyConfig configures entropy sources for secure domain generation
type EntropyConfig struct {
	// RequiredSources is the minimum number of entropy sources required
	RequiredSources int `yaml:"required_sources"`

	// MinQualityScore is the minimum aggregate quality score required
	MinQualityScore float64 `yaml:"min_quality_score"`

	// RefreshInterval is how often to refresh entropy
	RefreshInterval time.Duration `yaml:"refresh_interval"`

	// Sources is a list of entropy source configurations
	Sources []EntropySourceConfig `yaml:"sources"`
}

// EntropySourceConfig contains configuration for a specific entropy source
type EntropySourceConfig struct {
	// Type specifies the entropy source type
	Type string `yaml:"type"`

	// Enabled determines whether this source is active
	Enabled bool `yaml:"enabled"`

	// Weight determines the influence of this source on the final entropy
	Weight float64 `yaml:"weight"`

	// Config contains source-specific configuration
	Config map[string]interface{} `yaml:"config"`
}

// DynamicDiscoveryConfig configures dynamic discovery mechanisms
type DynamicDiscoveryConfig struct {
	// PeerDiscovery configures peer-based discovery
	PeerDiscovery PeerDiscoveryConfig `yaml:"peer_discovery"`

	// BlockchainDiscovery configures blockchain-based discovery
	BlockchainDiscovery BlockchainDiscoveryConfig `yaml:"blockchain_discovery"`

	// SteganographicChannels configures steganographic channels
	SteganographicChannels SteganographicConfig `yaml:"steganographic_channels"`

	// DomainGeneration configures domain generation algorithms
	DomainGeneration DGAConfiguration `yaml:"domain_generation"`

	// ChannelDiversity is the minimum number of independent channels that must succeed
	ChannelDiversity int `yaml:"channel_diversity"`
}

// PeerDiscoveryConfig configures peer-based discovery mechanisms
type PeerDiscoveryConfig struct {
	// Enabled determines whether peer discovery is active
	Enabled bool `yaml:"enabled"`

	// Protocols is a list of peer discovery protocols to use
	Protocols []string `yaml:"protocols"`

	// BootstrapTimeout is the maximum time to wait for peer discovery
	BootstrapTimeout time.Duration `yaml:"bootstrap_timeout"`

	// GossipInterval is how often to exchange peers
	GossipInterval time.Duration `yaml:"gossip_interval"`

	// MaxPeers is the maximum number of peers to track
	MaxPeers int `yaml:"max_peers"`
}

// BlockchainDiscoveryConfig configures blockchain-based discovery
type BlockchainDiscoveryConfig struct {
	// Enabled determines whether blockchain discovery is active
	Enabled bool `yaml:"enabled"`

	// Networks is a list of blockchain networks to use
	Networks []string `yaml:"networks"`

	// UpdateInterval is how often to check for new information
	UpdateInterval time.Duration `yaml:"update_interval"`

	// ContractAddresses maps network names to smart contract addresses
	ContractAddresses map[string]string `yaml:"contract_addresses"`

	// ConsensusThreshold is the minimum number of networks that must agree
	ConsensusThreshold int `yaml:"consensus_threshold"`
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
	// URLs is a mapping of provider names to their DoH endpoints
	// SECURITY: No static URLs - these must be dynamically generated
	URLs map[string]string `yaml:"urls"`

	// ServerNames is a mapping of provider names to their SNI values
	// SECURITY: No static server names - these must be dynamically generated
	ServerNames map[string]string `yaml:"server_names"`

	// QueryTimeout is the maximum time to wait for a DoH query
	QueryTimeout time.Duration `yaml:"query_timeout"`

	// MaxRetries is the number of retries for failed queries
	MaxRetries int `yaml:"max_retries"`

	// DomainGeneration configures secure domain generation for DoH providers
	DomainGeneration DGAConfiguration `yaml:"domain_generation"`

	// Hardened: Multi-channel discovery configuration
	DiscoveryChannels      DiscoveryConfig      `yaml:"discovery_channels"`
	SteganographyEndpoints SteganographicConfig `yaml:"steganography_endpoints"`
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

// SteganographicConfig configures steganographic channels for bootstrap discovery
type SteganographicConfig struct {
	// Enabled determines whether steganographic discovery is active
	Enabled bool `yaml:"enabled"`

	// Channels configures different steganographic channels
	Channels []SteganographicChannel `yaml:"channels"`

	// RotationInterval is how often to rotate through channels
	RotationInterval time.Duration `yaml:"rotation_interval"`

	// SECURITY: No static endpoints - must be dynamically discovered/generated
}

// SteganographicChannel represents a steganographic channel for bootstrap discovery
type SteganographicChannel struct {
	// Type is the type of steganographic channel (e.g., "image", "audio", "text")
	Type string `yaml:"type"`

	// Algorithm is the steganographic algorithm to use
	Algorithm string `yaml:"algorithm"`

	// ExtractionKey is the cryptographic key for extracting data
	ExtractionKey []byte `yaml:"extraction_key,omitempty"`

	// SourcePattern is a pattern for dynamically generating sources
	SourcePattern string `yaml:"source_pattern"`
}

// DGAConfiguration contains settings for domain generation algorithms
type DGAConfiguration struct {
	Algorithm         string   `yaml:"algorithm"`
	SeedRotationHours int      `yaml:"seed_rotation_hours"`
	TLDs              []string `yaml:"valid_tlds"`
	ClientSecret      []byte   `yaml:"client_secret"`

	// EntropyMixing is the method to combine entropy sources
	EntropyMixing string `yaml:"entropy_mixing"`

	// DomainCount is how many domains to generate per rotation
	DomainCount int `yaml:"domain_count"`

	// ValidationMethod is how to validate generated domains
	ValidationMethod string `yaml:"validation_method"`

	// PerLocationSalting enables location-specific salting for resistant against regional blocking
	PerLocationSalting bool `yaml:"per_location_salting"`
}

// DomainFrontingConfig contains configuration for domain fronting bootstrap discovery
type DomainFrontingConfig struct {
	// FrontDomains is a list of domains to use for domain fronting
	// SECURITY: No static domains - these must be dynamically generated

	// TargetDomains is a list of actual bootstrap service domains
	// SECURITY: No static domains - these must be dynamically generated

	// FrontCDNs is a mapping of CDN names to their front domains
	// SECURITY: No static CDN mapping - these must be dynamically discovered

	// DomainGeneration configures secure domain generation for fronting
	DomainGeneration DGAConfiguration `yaml:"domain_generation"`

	// RotationInterval is how often to rotate through front domains
	RotationInterval time.Duration `yaml:"rotation_interval"`

	// ConnectTimeout is the timeout for connection attempts
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// WellKnownConfig contains configuration for well-known endpoints discovery
type WellKnownConfig struct {
	// Endpoints is a list of well-known URLs to query for bootstrap information
	// SECURITY: No static endpoints - these must be dynamically generated

	// EndpointGeneration configures secure endpoint generation
	EndpointGeneration DGAConfiguration `yaml:"endpoint_generation"`

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

	// RotationStrategy controls how IPs are rotated to prevent tracking
	RotationStrategy string `yaml:"rotation_strategy"`

	// VerificationMethod is how to verify the IPs are still valid
	VerificationMethod string `yaml:"verification_method"`
}

// DiscoveryResult encapsulates the results of a bootstrap discovery operation
type DiscoveryResult struct {
	// Addresses is the list of discovered addresses
	Addresses []string

	// Source is the provider that discovered these addresses
	Source string

	// Error is non-nil if the discovery attempt failed
	Error error

	// ChannelType indicates which discovery channel produced this result
	ChannelType string

	// EntropySource describes the entropy used for discovery
	EntropySource string
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

	// Track which discovery channel provided each address
	addressSources map[string]string

	// Generator for cryptographically secure addresses
	secureGenerator DynamicAddressGenerator
}

// DynamicAddressGenerator defines the interface for dynamic address generation
type DynamicAddressGenerator interface {
	// GenerateAddresses generates a set of bootstrap addresses
	GenerateAddresses(ctx context.Context, entropyBundle *EntropyBundle, count int) ([]string, error)

	// ValidateAddress checks if an address is still valid
	ValidateAddress(ctx context.Context, address string) (bool, error)
}

// NewSecureRandomBytes generates secure random bytes for entropy
func NewSecureRandomBytes(size int) ([]byte, error) {
	bytes := make([]byte, size)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	return bytes, nil
}

// NewIPPool creates a new IP pool with secure address generation
func NewIPPool(config IPPoolConfig, logger Logger, generator DynamicAddressGenerator) *IPPool {
	return &IPPool{
		addresses:       make(map[string]time.Time),
		addressSources:  make(map[string]string),
		mutex:           &sync.RWMutex{},
		maxSize:         config.MaxSize,
		minSize:         config.MinSize,
		refreshInterval: config.RefreshInterval,
		persistPath:     config.PersistPath,
		logger:          logger,
		lastUpdate:      time.Time{},
		secureGenerator: generator,
	}
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

// AddAddressesWithSource adds addresses with their discovery source
func (p *IPPool) AddAddressesWithSource(addresses []string, source string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	now := time.Now()
	for _, addr := range addresses {
		if len(p.addresses) < p.maxSize {
			p.addresses[addr] = now
			p.addressSources[addr] = source
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

// GetAddressesBySource returns addresses from a specific source
func (p *IPPool) GetAddressesBySource(source string) []string {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	var addresses []string
	for addr, src := range p.addressSources {
		if src == source {
			addresses = append(addresses, addr)
		}
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
		Addresses      map[string]time.Time `json:"addresses"`
		AddressSources map[string]string    `json:"address_sources"`
		LastUpdate     time.Time            `json:"last_update"`
	}{
		Addresses:      p.addresses,
		AddressSources: p.addressSources,
		LastUpdate:     p.lastUpdate,
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
		Addresses      map[string]time.Time `json:"addresses"`
		AddressSources map[string]string    `json:"address_sources"`
		LastUpdate     time.Time            `json:"last_update"`
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

	p.addressSources = data.AddressSources
	if p.addressSources == nil {
		p.addressSources = make(map[string]string)
	}

	p.lastUpdate = data.LastUpdate

	return nil
}

// GenerateSecureAddresses uses the secure generator to create new addresses
func (p *IPPool) GenerateSecureAddresses(ctx context.Context, entropyBundle *EntropyBundle, count int) ([]string, error) {
	if p.secureGenerator == nil {
		return nil, fmt.Errorf("no secure address generator configured")
	}

	return p.secureGenerator.GenerateAddresses(ctx, entropyBundle, count)
}

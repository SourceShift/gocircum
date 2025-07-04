package config

import (
	"crypto/x509"
	"fmt"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FileConfig represents the top-level structure of a configuration file.
type FileConfig struct {
	Proxy          *Proxy        `yaml:"proxy,omitempty"`
	Fingerprints   []Fingerprint `yaml:"fingerprints"`
	DoHProviders   []DoHProvider `yaml:"doh_providers"`
	CanaryDomains  []string      `yaml:"canary_domains"`
	Disabled       bool          `yaml:"disabled,omitempty"`
	ConnectTimeout time.Duration `yaml:"connect_timeout,omitempty"`
}

func (c *FileConfig) Validate() error {
	if len(c.Fingerprints) == 0 {
		return fmt.Errorf("no fingerprints defined in configuration")
	}
	if len(c.DoHProviders) == 0 {
		return fmt.Errorf("security policy violation: at least one DoH provider must be configured to prevent DNS-based blocking")
	}
	if len(c.CanaryDomains) == 0 {
		return fmt.Errorf("at least one canary_domain must be configured for strategy testing")
	}
	// Here you can add more validation logic for each fingerprint
	for _, fp := range c.Fingerprints {
		if err := fp.Validate(); err != nil {
			return fmt.Errorf("validation failed for fingerprint '%s': %w", fp.ID, err)
		}
	}
	return nil
}

// Proxy defines the configuration for the SOCKS5 proxy server.
type Proxy struct {
	ListenAddr string `yaml:"listen_addr"`
}

// DomainFronting configures domain fronting behavior.
type DomainFronting struct {
	Enabled         bool   `yaml:"enabled"`
	DiscoveryMethod string `yaml:"discovery_method"` // e.g., "dga", "covert_cdn", "social_steganography"
	// Runtime-only fields - not serialized to YAML
	FrontDomain  string `yaml:"-"` // Domain used for fronting
	CovertTarget string `yaml:"-"` // Actual target domain
}

// Fingerprint defines a complete connection profile.
type Fingerprint struct {
	ID             string          `yaml:"id"`
	Description    string          `yaml:"description"`
	DomainFronting *DomainFronting `yaml:"domain_fronting,omitempty"`
	Transport      Transport       `yaml:"transport"`
	TLS            TLS             `yaml:"tls"`
}

func (f *Fingerprint) Validate() error {
	if f.ID == "" {
		return fmt.Errorf("fingerprint ID cannot be empty")
	}

	// Security Policy: All strategies MUST use domain fronting.
	// Direct connections with SNI leaks are not permitted.
	if f.DomainFronting == nil || !f.DomainFronting.Enabled {
		return fmt.Errorf("security policy violation: domain_fronting must be enabled for all strategies")
	}

	// If domain fronting is enabled, ensure a discovery method is specified
	if f.DomainFronting.DiscoveryMethod == "" {
		return fmt.Errorf("discovery_method must be set when domain_fronting is enabled")
	}

	// Validate the discovery method
	validMethods := map[string]bool{
		"dga":                  true,
		"covert_cdn":           true,
		"social_steganography": true,
		"blockchain_consensus": true,
		"peer_gossip":          true,
	}

	if !validMethods[f.DomainFronting.DiscoveryMethod] {
		return fmt.Errorf("invalid discovery_method: %s", f.DomainFronting.DiscoveryMethod)
	}

	// Add more validation for Transport and TLS fields
	if err := f.TLS.Validate(); err != nil {
		return fmt.Errorf("tls validation failed: %w", err)
	}

	return nil
}

// Transport configures the low-level connection.
type Transport struct {
	Protocol      string         `yaml:"protocol"`
	Fragmentation *Fragmentation `yaml:"fragmentation,omitempty"`
}

// Fragmentation configuration for transport layer.
type Fragmentation struct {
	Enabled     bool     `yaml:"enabled"`
	Strategy    string   `yaml:"strategy"`
	NumPackets  int      `yaml:"num_packets,omitempty"`
	Delay       int      `yaml:"delay,omitempty"`
	PacketSizes [][2]int `yaml:"packet_sizes"`
	DelayMs     [2]int   `yaml:"delay_ms"`
	Algorithm   string   `yaml:"algorithm,omitempty"`
}

// TLS configures the TLS layer.
type TLS struct {
	Library         string         `yaml:"library,omitempty"` // e.g., "utls"
	ClientHelloID   string         `yaml:"client_hello_id,omitempty"`
	UserAgent       string         `yaml:"user_agent,omitempty"`
	ServerName      string         `yaml:"server_name,omitempty"`
	RootCAs         *x509.CertPool `yaml:"-"`                     // This will not be marshalled from/to YAML.
	MinVersion      string         `yaml:"min_version,omitempty"` // e.g., "1.2"
	MaxVersion      string         `yaml:"max_version,omitempty"` // e.g., "1.3"
	CipherSuites    []string       `yaml:"cipher_suites,omitempty"`
	ALPN            []string       `yaml:"alpn,omitempty"`
	ECHEnabled      bool           `yaml:"ech_enabled,omitempty"`
	ECHConfig       string         `yaml:"ech_config,omitempty"`
	UTLSParrot      string         `yaml:"utls_parrot,omitempty"`
	QUICNextProtos  []string       `yaml:"quic_next_protos,omitempty"`
	QUICIdleTimeout time.Duration  `yaml:"quic_idle_timeout,omitempty"`

	// Internal field to store the raw YAML content for validation
	rawContent []byte `yaml:"-"`
}

// UnmarshalYAML implements the yaml.Unmarshaler interface.
func (t *TLS) UnmarshalYAML(unmarshal func(interface{}) error) error {
	// Store the raw content for security validation
	var rawMap map[string]interface{}
	if err := unmarshal(&rawMap); err != nil {
		return err
	}

	// Check for insecure_skip_verify in the raw map
	if _, exists := rawMap["insecure_skip_verify"]; exists {
		return fmt.Errorf("security policy violation: certificate validation bypassing (insecure_skip_verify) is not allowed")
	}

	// Marshal the raw map to keep a copy of the original content
	rawContent, err := yaml.Marshal(rawMap)
	if err != nil {
		return err
	}

	// Use a temporary type to avoid infinite recursion
	type TLSAlias TLS
	alias := (*TLSAlias)(t)
	if err := unmarshal(alias); err != nil {
		return err
	}

	// Store the raw content for later use in validation
	t.rawContent = rawContent

	return nil
}

// Validate ensures the TLS configuration is valid.
func (t *TLS) Validate() error {
	// A TLS block might be empty in the config, in which case it's a no-op.
	// We only validate if there are properties set.
	// The dialer factory is responsible for enforcing TLS if the block is present.
	if t.Library == "" && t.ClientHelloID == "" {
		return nil // Nothing to validate
	}

	// Security Policy: The only permitted client-side library is 'utls' to
	// prevent fingerprinting of the standard Go TLS implementation.
	if t.Library != "utls" {
		return fmt.Errorf("security policy violation: tls.library must be 'utls', but got '%s'", t.Library)
	}
	if t.ClientHelloID == "" {
		return fmt.Errorf("security policy violation: tls.client_hello_id must be specified")
	}

	return nil
}

// P2PDiscovery holds configuration for peer-to-peer network discovery
type P2PDiscovery struct {
	Network               string   `yaml:"network"`                 // Network type (ipfs, libp2p, i2p)
	BootstrapPeers        []string `yaml:"bootstrap_peers"`         // Initial peers to connect to
	MinimumPeerReputation int      `yaml:"minimum_peer_reputation"` // Minimum reputation score for peers
	DiscoveryInterval     string   `yaml:"discovery_interval"`      // How often to query the network
	MaxPeers              int      `yaml:"max_peers"`               // Maximum number of peers to connect to
}

// DoHProvider holds the configuration for a single DNS-over-HTTPS provider.
type DoHProvider struct {
	Name                 string             `yaml:"name"`
	URL                  string             `yaml:"url"`
	ServerName           string             `yaml:"server_name"`
	Bootstrap            []string           `yaml:"bootstrap"`
	BootstrapPool        []string           `yaml:"bootstrap_pool,omitempty"`
	BootstrapRotationSec int                `yaml:"bootstrap_rotation_sec,omitempty"`
	RootCA               string             `yaml:"root_ca,omitempty"`
	FrontDomain          string             `yaml:"front_domain,omitempty"`
	ObfuscatedBootstrap  bool               `yaml:"obfuscated_bootstrap,omitempty"`
	BootstrapDiscovery   BootstrapDiscovery `yaml:"bootstrap_discovery,omitempty"`
	MaxBootstrapFailures int                `yaml:"max_bootstrap_failures,omitempty"`
	BootstrapHealthCheck bool               `yaml:"bootstrap_health_check,omitempty"`

	// New fields for decentralized/discovered providers
	DGAConfig              *DGAConfig              `yaml:"dga_config,omitempty"`
	SteganographicChannels []SteganographicChannel `yaml:"steganographic_channels,omitempty"`
	BlockchainDiscovery    []BlockchainDiscovery   `yaml:"blockchain_discovery,omitempty"`
	PeerDiscovery          *PeerDiscovery          `yaml:"peer_discovery,omitempty"`
	P2PDiscovery           []P2PDiscovery          `yaml:"p2p_discovery,omitempty"`
}

// BootstrapDiscovery contains settings for dynamic discovery of bootstrap IPs
type BootstrapDiscovery struct {
	EnableDNSOverHTTPS   bool     `yaml:"enable_dns_over_https"`
	EnableWellKnownPaths bool     `yaml:"enable_well_known_paths"`
	AlternateResolvers   []string `yaml:"alternate_resolvers"`
	PeerDiscoveryEnabled bool     `yaml:"peer_discovery_enabled"`
}

// DGAConfig holds configuration for the domain generation algorithm
type DGAConfig struct {
	Enabled      bool              `yaml:"enabled"`
	Algorithm    string            `yaml:"algorithm"`     // e.g., "mathematical", "dictionary", "hybrid"
	Seed         string            `yaml:"seed"`          // Base seed for the algorithm
	RotationTime int               `yaml:"rotation_time"` // Rotation time in minutes
	Parameters   map[string]string `yaml:"parameters"`    // Algorithm-specific parameters
	DomainCount  int               `yaml:"domain_count"`  // Number of domains to generate
}

// SteganographicChannel holds config for steganographic discovery
type SteganographicChannel struct {
	Platform            string   `yaml:"platform"`
	SearchPatterns      []string `yaml:"search_patterns,omitempty"`
	ExtractionAlgorithm string   `yaml:"extraction_algorithm,omitempty"`
	Subreddits          []string `yaml:"subreddits,omitempty"`
	Pattern             string   `yaml:"pattern,omitempty"`
}

// BlockchainDiscovery holds config for blockchain-based provider discovery
type BlockchainDiscovery struct {
	Network          string `yaml:"network"`
	ContractAddress  string `yaml:"contract_address"`
	ValidationMethod string `yaml:"validation_method"`
}

// PeerDiscovery holds config for peer-to-peer provider discovery
type PeerDiscovery struct {
	BootstrapMethod string `yaml:"bootstrap_method"`
	GossipProtocol  string `yaml:"gossip_protocol"`
	PeerValidation  string `yaml:"peer_validation"`
}

// SecureDestroy securely clears sensitive data from memory
func (f *Fingerprint) SecureDestroy() {
	// Explicitly zero sensitive string fields
	f.ID = strings.Repeat("\x00", len(f.ID))
	f.Description = strings.Repeat("\x00", len(f.Description))

	if f.DomainFronting != nil {
		f.DomainFronting.SecureDestroy()
	}

	// Force garbage collection to clear old references
	runtime.GC()
}

// SecureDestroy securely clears DomainFronting data
func (df *DomainFronting) SecureDestroy() {
	df.DiscoveryMethod = strings.Repeat("\x00", len(df.DiscoveryMethod))
	df.FrontDomain = strings.Repeat("\x00", len(df.FrontDomain))
	df.CovertTarget = strings.Repeat("\x00", len(df.CovertTarget))
}

package config

import (
	"crypto/x509"
	"fmt"
	"time"
)

// FileConfig represents the top-level structure of a configuration file.
type FileConfig struct {
	Proxy          *Proxy        `yaml:"proxy,omitempty"`
	Fingerprints   []Fingerprint `yaml:"fingerprints"`
	DoHProviders   []DoHProvider `yaml:"doh_providers,omitempty"`
	CanaryDomains  []string      `yaml:"canary_domains,omitempty"`
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
	FrontDomain  string `yaml:"front_domain"`
	CovertTarget string `yaml:"covert_target"`
	Enabled      bool   `yaml:"enabled"`
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

	// If domain fronting is enabled, its properties must be valid.
	if f.DomainFronting.FrontDomain == "" {
		return fmt.Errorf("front_domain must be set when domain_fronting is enabled")
	}
	if f.DomainFronting.CovertTarget == "" {
		return fmt.Errorf("covert_target must be set when domain_fronting is enabled")
	}

	// Add more validation for Transport and TLS fields
	return nil
}

// Transport configures the low-level connection.
type Transport struct {
	Protocol      string         `yaml:"protocol"`
	Fragmentation *Fragmentation `yaml:"fragmentation,omitempty"`
}

// Fragmentation configures ClientHello fragmentation.
type Fragmentation struct {
	PacketSizes [][2]int `yaml:"packet_sizes"`
	DelayMs     [2]int   `yaml:"delay_ms"`
	Algorithm   string   `yaml:"algorithm,omitempty"`
}

// TLS configures the TLS layer.
type TLS struct {
	ServerName      string         `yaml:"server_name,omitempty"`     // Explicitly set SNI, overrides defaults.
	Library         string         `yaml:"library,omitempty"`         // go-stdlib, utls
	ClientHelloID   string         `yaml:"client_hello_id,omitempty"` // e.g., "HelloChrome_102"
	UserAgent       string         `yaml:"user_agent,omitempty"`
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
}

// DoHProvider holds the configuration for a single DNS-over-HTTPS provider.
type DoHProvider struct {
	Name        string   `yaml:"name"`
	URL         string   `yaml:"url"`
	ServerName  string   `yaml:"server_name"` // The real DoH server name, for the Host header.
	Bootstrap   []string `yaml:"bootstrap"`   // IPs of the FrontDomain, not the DoH server.
	RootCA      string   `yaml:"root_ca,omitempty"`
	FrontDomain string   `yaml:"front_domain,omitempty"` // The benign domain for TLS SNI.
}

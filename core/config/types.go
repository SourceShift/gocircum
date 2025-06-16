package config

// FileConfig represents the top-level structure of a configuration file.
type FileConfig struct {
	Proxy        *Proxy        `yaml:"proxy,omitempty"`
	Fingerprints []Fingerprint `yaml:"fingerprints"`
}

// Proxy defines the configuration for the SOCKS5 proxy server.
type Proxy struct {
	ListenAddr string `yaml:"listen_addr"`
}

// Fingerprint defines a complete connection profile.
type Fingerprint struct {
	ID          string    `yaml:"id"`
	Description string    `yaml:"description"`
	Transport   Transport `yaml:"transport"`
	TLS         TLS       `yaml:"tls"`
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
}

// TLS configures the TLS layer.
type TLS struct {
	Library       string `yaml:"library"`
	ClientHelloID string `yaml:"client_hello_id"`
	MinVersion    string `yaml:"min_version,omitempty"`
	MaxVersion    string `yaml:"max_version,omitempty"`
	// SkipVerify controls whether the client validates the server's certificate
	// chain and host name. If SkipVerify is true, TLS accepts any certificate
	// presented by the server and any host name in that certificate.
	// In this mode, TLS is susceptible to man-in-the-middle attacks.
	// This should be used only for testing.
	SkipVerify bool `yaml:"skip_verify,omitempty"`
}

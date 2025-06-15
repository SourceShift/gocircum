package config

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
	MinVersion    string `yaml:"min_version"`
	MaxVersion    string `yaml:"max_version"`
}

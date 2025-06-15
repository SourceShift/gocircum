package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Config represents the top-level configuration structure.
type Config struct {
	Strategies []Strategy `yaml:"strategies"`
}

// Strategy defines a single evasion strategy.
type Strategy struct {
	Name       string       `yaml:"name"`
	Enabled    bool         `yaml:"enabled"`
	Transport  Transport    `yaml:"transport"`
	TLS        TLS          `yaml:"tls"`
	Middleware []Middleware `yaml:"middleware,omitempty"`
}

// Transport specifies the network transport parameters.
type Transport struct {
	Protocol string `yaml:"protocol"` // "tcp" or "quic"
}

// TLS specifies the TLS handshake parameters.
type TLS struct {
	Library       string `yaml:"library"`         // "go-stdlib", "utls", or "uquic"
	ClientHelloID string `yaml:"client_hello_id"` // e.g., "HelloChrome_Auto"
}

// Middleware defines a transformation to be applied to the transport.
type Middleware struct {
	Name       string      `yaml:"name"`
	Parameters MParameters `yaml:"parameters,omitempty"`
}

// MParameters holds parameters for a specific middleware.
type MParameters struct {
	PacketSizes []int `yaml:"packet_sizes,omitempty"`
	Delay       int   `yaml:"delay,omitempty"`
}

func (c *Config) Validate() error {
	if len(c.Strategies) == 0 {
		return fmt.Errorf("no strategies found in configuration")
	}

	for i, s := range c.Strategies {
		if s.Name == "" {
			return fmt.Errorf("strategy %d is missing a name", i)
		}
		if s.Transport.Protocol != "tcp" && s.Transport.Protocol != "quic" {
			return fmt.Errorf("strategy '%s' has an invalid transport protocol: %s", s.Name, s.Transport.Protocol)
		}
		if s.TLS.Library != "go-stdlib" && s.TLS.Library != "utls" && s.TLS.Library != "uquic" {
			return fmt.Errorf("strategy '%s' has an invalid TLS library: %s", s.Name, s.TLS.Library)
		}
		if s.TLS.ClientHelloID == "" {
			return fmt.Errorf("strategy '%s' is missing a client_hello_id", s.Name)
		}
		for _, m := range s.Middleware {
			if m.Name != "packet_fragmentation" {
				return fmt.Errorf("strategy '%s' has an unsupported middleware: %s", s.Name, m.Name)
			}
		}
	}
	return nil
}

// LoadConfig reads a YAML file from the given path and returns a Config object.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal yaml: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	// TODO: Add validation logic here

	return &config, nil
}

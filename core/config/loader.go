package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// FileConfig is the top-level structure for the YAML configuration file.
type FileConfig struct {
	Fingerprints []*Fingerprint `yaml:"strategies"`
}

// LoadFingerprintsFromFile loads a list of fingerprints from a YAML file.
func LoadFingerprintsFromFile(filePath string) ([]*Fingerprint, error) {
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file '%s': %w", filePath, err)
	}

	var config FileConfig
	err = yaml.Unmarshal(buf, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config file '%s': %w", filePath, err)
	}

	return config.Fingerprints, nil
}

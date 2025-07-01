package bootstrap

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ProviderFactory creates bootstrap providers from configuration
type ProviderFactory struct {
	logger Logger
}

// NewProviderFactory creates a new provider factory with the given logger
func NewProviderFactory(logger Logger) *ProviderFactory {
	return &ProviderFactory{
		logger: logger,
	}
}

// CreateProvider creates a bootstrap provider of the specified type
func (f *ProviderFactory) CreateProvider(config ProviderConfig) (BootstrapProvider, error) {
	switch config.Type {
	case "doh":
		return f.createDoHProvider(config)
	case "domain_fronting":
		return f.createDomainFrontingProvider(config)
	case "well_known":
		return f.createWellKnownProvider(config)
	default:
		return nil, fmt.Errorf("unknown bootstrap provider type: %s", config.Type)
	}
}

// createDoHProvider creates a DNS-over-HTTPS bootstrap provider
func (f *ProviderFactory) createDoHProvider(config ProviderConfig) (BootstrapProvider, error) {
	// Will be implemented in the next subtask
	return nil, fmt.Errorf("doh provider implementation not yet available")
}

// createDomainFrontingProvider creates a domain fronting bootstrap provider
func (f *ProviderFactory) createDomainFrontingProvider(config ProviderConfig) (BootstrapProvider, error) {
	// Will be implemented in the next subtask
	return nil, fmt.Errorf("domain fronting provider implementation not yet available")
}

// createWellKnownProvider creates a well-known endpoints bootstrap provider
func (f *ProviderFactory) createWellKnownProvider(config ProviderConfig) (BootstrapProvider, error) {
	// Will be implemented in the next subtask
	return nil, fmt.Errorf("well-known provider implementation not yet available")
}

// LoadConfiguration loads bootstrap configuration from a YAML file
func LoadConfiguration(path string) (*BootstrapConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read bootstrap config file: %w", err)
	}

	// First unmarshal into a map to extract and log the deprecated fallback_addresses field
	var configMap map[string]interface{}
	if err := yaml.Unmarshal(data, &configMap); err != nil {
		return nil, fmt.Errorf("failed to parse bootstrap config: %w", err)
	}

	// Check for fallback_addresses and remove it
	delete(configMap, "fallback_addresses")

	// Now unmarshal into the actual struct
	var config BootstrapConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse bootstrap config: %w", err)
	}

	return &config, nil
}

// CreateProvidersFromConfig creates bootstrap providers from a config file
func (f *ProviderFactory) CreateProvidersFromConfig(configPath string) ([]BootstrapProvider, error) {
	config, err := LoadConfiguration(configPath)
	if err != nil {
		return nil, err
	}

	var providers []BootstrapProvider
	for _, providerConfig := range config.Providers {
		if !providerConfig.Enabled {
			f.logger.Debug("Skipping disabled bootstrap provider", "type", providerConfig.Type)
			continue
		}

		provider, err := f.CreateProvider(providerConfig)
		if err != nil {
			f.logger.Warn("Failed to create bootstrap provider",
				"type", providerConfig.Type,
				"error", err)
			continue
		}

		providers = append(providers, provider)
	}

	if len(providers) == 0 {
		return nil, fmt.Errorf("no enabled bootstrap providers found in configuration")
	}

	return providers, nil
}

// InitializeFromConfig creates and initializes a BootstrapManager from a config file
func InitializeFromConfig(configPath string, logger Logger) (*Manager, error) {
	config, err := LoadConfiguration(configPath)
	if err != nil {
		return nil, err
	}

	manager, err := NewManager(*config, logger)
	if err != nil {
		return nil, err
	}

	factory := NewProviderFactory(logger)

	for _, providerConfig := range config.Providers {
		if !providerConfig.Enabled {
			logger.Debug("Skipping disabled bootstrap provider", "type", providerConfig.Type)
			continue
		}

		provider, err := factory.CreateProvider(providerConfig)
		if err != nil {
			logger.Warn("Failed to create bootstrap provider",
				"type", providerConfig.Type,
				"error", err)
			continue
		}

		manager.RegisterProvider(provider)
	}

	// Initialize IP pool if configured
	var ipPoolConfig IPPoolConfig
	for _, providerConfig := range config.Providers {
		if providerConfig.Type == "ip_pool" && providerConfig.Enabled {
			if err := decodeConfig(providerConfig.Config, &ipPoolConfig); err != nil {
				logger.Warn("Failed to decode IP pool config", "error", err)
				continue
			}

			if err := manager.InitializeIPPool(ipPoolConfig); err != nil {
				logger.Warn("Failed to initialize IP pool", "error", err)
				// Continue even if IP pool fails
			}
			break
		}
	}

	return manager, nil
}

// decodeConfig is a helper function to decode configuration maps into structs
func decodeConfig(configMap map[string]interface{}, result interface{}) error {
	// Marshal the map back to JSON
	jsonBytes, err := yaml.Marshal(configMap)
	if err != nil {
		return fmt.Errorf("failed to marshal config map: %w", err)
	}

	// Unmarshal JSON into the target struct
	if err := yaml.Unmarshal(jsonBytes, result); err != nil {
		return fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return nil
}

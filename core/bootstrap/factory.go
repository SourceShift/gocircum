package bootstrap

import (
	"fmt"
	"os"

	"github.com/gocircum/gocircum/pkg/logging"
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

// CreateProvidersFromConfig creates bootstrap providers from a configuration file
func (f *ProviderFactory) CreateProvidersFromConfig(config *BootstrapConfig, manager *Manager) error {
	var errors []error

	for _, providerConfig := range config.Providers {
		if !providerConfig.Enabled {
			f.logger.Debug("Skipping disabled bootstrap provider", "type", providerConfig.Type)
			continue
		}

		provider, err := f.CreateProvider(providerConfig)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to create %s provider: %w", providerConfig.Type, err))
			f.logger.Warn("Failed to create bootstrap provider",
				"type", providerConfig.Type,
				"error", err)
			continue
		}

		manager.RegisterProvider(provider)
		f.logger.Debug("Registered bootstrap provider", "type", providerConfig.Type)
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to create some providers: %v", errors)
	}

	return nil
}

// InitializeFromConfig initializes a bootstrap manager from a config file
func InitializeFromConfig(configPath string, logger logging.Logger) (*Manager, error) {
	config, err := LoadConfiguration(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load bootstrap config: %w", err)
	}

	// Create the manager
	manager, err := NewManager(config, logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create bootstrap manager: %w", err)
	}

	// Initialize the IP pool if configured
	if config.IPPoolConfig != nil {
		err = manager.InitializeIPPool(*config.IPPoolConfig)
		if err != nil {
			logger.Warn("Failed to initialize IP pool", "error", err)
		}
	}

	// Register discovery channels if enabled
	if config.UseDiscoveryChannels {
		err = manager.RegisterDiscoveryChannels()
		if err != nil {
			logger.Warn("Failed to register discovery channels", "error", err)
		}
	}

	// Create and register bootstrap providers
	factory := NewProviderFactory(logger)
	err = factory.CreateProvidersFromConfig(config, manager)
	if err != nil {
		logger.Warn("Failed to create some bootstrap providers", "error", err)
	}

	return manager, nil
}

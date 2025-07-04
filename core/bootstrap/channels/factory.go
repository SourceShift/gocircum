package channels

import (
	"fmt"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
)

// ChannelFactory creates and registers discovery channels
type ChannelFactory struct {
	logger logging.Logger
}

// ChannelConfig represents the configuration for discovery channels
type ChannelConfig struct {
	Enabled  bool                   `json:"enabled" yaml:"enabled"`
	Priority int                    `json:"priority" yaml:"priority"`
	Timeout  string                 `json:"timeout" yaml:"timeout"`
	Type     string                 `json:"type" yaml:"type"`
	Options  map[string]interface{} `json:"options" yaml:"options"`
}

// NewChannelFactory creates a new channel factory
func NewChannelFactory(logger logging.Logger) *ChannelFactory {
	if logger == nil {
		logger = logging.GetLogger()
	}

	return &ChannelFactory{
		logger: logger,
	}
}

// CreateChannel creates a discovery channel based on the provided config
func (f *ChannelFactory) CreateChannel(config ChannelConfig) (DiscoveryChannel, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("channel is disabled")
	}

	// Parse timeout
	timeout := 30 * time.Second
	if config.Timeout != "" {
		parsedTimeout, err := time.ParseDuration(config.Timeout)
		if err != nil {
			f.logger.Warn("Invalid timeout in channel config, using default",
				"timeout", config.Timeout,
				"default", timeout,
				"error", err)
		} else {
			timeout = parsedTimeout
		}
	}

	// Create channel based on type
	switch config.Type {
	case "dns":
		return f.createDNSChannel(config.Priority, timeout, config.Options)
	case "https":
		return f.createHTTPSChannel(config.Priority, timeout, config.Options)
	case "peer_exchange":
		return f.createPeerExchangeChannel(config.Priority, timeout, config.Options)
	default:
		return nil, fmt.Errorf("unknown channel type: %s", config.Type)
	}
}

// createDNSChannel creates a DNS-based discovery channel
func (f *ChannelFactory) createDNSChannel(priority int, timeout time.Duration, options map[string]interface{}) (DiscoveryChannel, error) {
	opts := DNSChannelOptions{
		Priority: priority,
		Timeout:  timeout,
	}

	// Extract options
	if domains, ok := options["domains_per_iteration"].(int); ok {
		opts.DomainsPerIteration = domains
	}

	if recordTypes, ok := options["record_types"].([]string); ok {
		opts.RecordTypes = recordTypes
	}

	// Create a simple domain generator with default domains
	domains := []string{"bootstrap.example.com", "discovery.example.com"}
	if domainList, ok := options["domains"].([]string); ok && len(domainList) > 0 {
		domains = domainList
	} else if domainListInterface, ok := options["domains"].([]interface{}); ok {
		// Handle yaml/json parsing which might give us []interface{} instead of []string
		domains = make([]string, 0, len(domainListInterface))
		for _, domain := range domainListInterface {
			if domainStr, ok := domain.(string); ok {
				domains = append(domains, domainStr)
			}
		}
	}

	domainGen := NewSimpleDomainGenerator(domains)

	return NewDNSDiscoveryChannel(domainGen, opts, f.logger), nil
}

// createHTTPSChannel creates an HTTPS-based discovery channel
func (f *ChannelFactory) createHTTPSChannel(priority int, timeout time.Duration, options map[string]interface{}) (DiscoveryChannel, error) {
	opts := HTTPSChannelOptions{
		Priority: priority,
		Timeout:  timeout,
	}

	// Extract options
	if pathTemplate, ok := options["path_template"].(string); ok {
		opts.PathTemplate = pathTemplate
	}

	if clientTimeout, ok := options["client_timeout"].(string); ok {
		parsedTimeout, err := time.ParseDuration(clientTimeout)
		if err == nil {
			opts.ClientTimeout = parsedTimeout
		}
	}

	// Create a simple domain generator with default domains
	domains := []string{"api.bootstrap.example.com", "discovery-api.example.com"}
	if domainList, ok := options["domains"].([]string); ok && len(domainList) > 0 {
		domains = domainList
	} else if domainListInterface, ok := options["domains"].([]interface{}); ok {
		// Handle yaml/json parsing which might give us []interface{} instead of []string
		domains = make([]string, 0, len(domainListInterface))
		for _, domain := range domainListInterface {
			if domainStr, ok := domain.(string); ok {
				domains = append(domains, domainStr)
			}
		}
	}

	domainGen := NewSimpleDomainGenerator(domains)

	return NewHTTPSDiscoveryChannel(domainGen, opts, f.logger), nil
}

// createPeerExchangeChannel creates a peer exchange discovery channel
func (f *ChannelFactory) createPeerExchangeChannel(priority int, timeout time.Duration, options map[string]interface{}) (DiscoveryChannel, error) {
	opts := PeerExchangeOptions{
		Priority: priority,
		Timeout:  timeout,
	}

	// Extract options
	if initialPeers, ok := options["initial_peers"].([]string); ok {
		opts.InitialPeers = initialPeers
	} else if initialPeersInterface, ok := options["initial_peers"].([]interface{}); ok {
		// Handle yaml/json parsing which might give us []interface{} instead of []string
		for _, peer := range initialPeersInterface {
			if peerStr, ok := peer.(string); ok {
				opts.InitialPeers = append(opts.InitialPeers, peerStr)
			}
		}
	}

	if refreshInterval, ok := options["refresh_interval"].(string); ok {
		parsedInterval, err := time.ParseDuration(refreshInterval)
		if err == nil {
			opts.RefreshInterval = parsedInterval
		}
	}

	if maxPeers, ok := options["max_peers"].(int); ok {
		opts.MaxPeers = maxPeers
	}

	return NewPeerExchangeChannel(opts, f.logger), nil
}

// RegisterChannelsFromConfig registers discovery channels with a manager based on configuration
func (f *ChannelFactory) RegisterChannelsFromConfig(manager *DiscoveryManager, configs []ChannelConfig) error {
	var registeredCount int
	var errors []string

	for _, config := range configs {
		channel, err := f.CreateChannel(config)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to create %s channel: %v", config.Type, err))
			continue
		}

		manager.RegisterChannel(channel)
		registeredCount++

		f.logger.Info("Registered discovery channel",
			"type", config.Type,
			"priority", channel.Priority(),
			"timeout", channel.Timeout())
	}

	if registeredCount == 0 && len(errors) > 0 {
		return fmt.Errorf("failed to register any channels: %v", errors)
	}

	f.logger.Info("Discovery channels registered", "count", registeredCount)
	return nil
}

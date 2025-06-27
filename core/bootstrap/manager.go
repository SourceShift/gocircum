package bootstrap

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sort"
	"sync"
	"time"
)

// Manager is responsible for orchestrating different bootstrap discovery methods
// and providing access to discovered bootstrap addresses
type Manager struct {
	providers      []BootstrapProvider
	cache          map[string]*BootstrapResult
	mutex          sync.RWMutex
	logger         Logger
	healthCheck    HealthCheckOptions
	fallbackAddrs  []string
	cacheTTL       time.Duration
	discoveryCount int
	ipPool         *IPPool
}

// NewManager creates a new bootstrap manager with the given configuration
func NewManager(config BootstrapConfig, logger Logger) (*Manager, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	m := &Manager{
		providers:     make([]BootstrapProvider, 0),
		cache:         make(map[string]*BootstrapResult),
		logger:        logger,
		healthCheck:   config.HealthCheck,
		fallbackAddrs: config.FallbackAddresses,
		cacheTTL:      config.CacheTTL,
	}

	// Set default TTL if not provided
	if m.cacheTTL == 0 {
		m.cacheTTL = 24 * time.Hour
	}

	return m, nil
}

// RegisterProvider adds a bootstrap provider to the manager
func (m *Manager) RegisterProvider(provider BootstrapProvider) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.providers = append(m.providers, provider)

	// Sort providers by priority (highest first)
	sort.Slice(m.providers, func(i, j int) bool {
		return m.providers[i].Priority() > m.providers[j].Priority()
	})
}

// DiscoverBootstraps performs bootstrap discovery using all registered providers
// and returns a list of unique bootstrap addresses
func (m *Manager) DiscoverBootstraps(ctx context.Context) ([]string, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if len(m.providers) == 0 {
		return m.fallbackAddrs, nil
	}

	var allAddresses []string
	var discoveryErrors []error

	// Increment discovery count for tracking attempts
	m.discoveryCount++

	// Check cache first
	validCacheEntries := m.getValidCacheEntries()
	if len(validCacheEntries) > 0 {
		m.logger.Debug("Using cached bootstrap addresses", "count", len(validCacheEntries))
		for _, entry := range validCacheEntries {
			allAddresses = append(allAddresses, entry.Addresses...)
		}
		return m.validateAndShuffle(allAddresses), nil
	}

	// Try each provider in order of priority
	for _, provider := range m.providers {
		select {
		case <-ctx.Done():
			return m.fallbackAddrs, ctx.Err()
		default:
			// Continue with discovery
		}

		m.logger.Debug("Discovering bootstrap addresses",
			"provider", provider.Name(),
			"priority", provider.Priority(),
			"attempt", m.discoveryCount)

		addresses, err := provider.Discover(ctx)
		if err != nil {
			m.logger.Warn("Bootstrap discovery failed",
				"provider", provider.Name(),
				"error", err)
			discoveryErrors = append(discoveryErrors, fmt.Errorf("provider %s: %w", provider.Name(), err))
			continue
		}

		if len(addresses) > 0 {
			m.logger.Info("Bootstrap addresses discovered",
				"provider", provider.Name(),
				"count", len(addresses))

			// Cache the result
			m.cache[provider.Name()] = &BootstrapResult{
				Provider:  provider.Name(),
				Addresses: addresses,
				Timestamp: time.Now(),
				TTL:       m.cacheTTL,
			}

			allAddresses = append(allAddresses, addresses...)
		}
	}

	// Health check addresses if configured
	if m.healthCheck.Enabled && len(allAddresses) > 0 {
		allAddresses = m.performHealthCheck(allAddresses)
	}

	// Fallback to static addresses if no addresses discovered
	if len(allAddresses) == 0 {
		m.logger.Warn("All bootstrap discovery methods failed, using fallback addresses",
			"errors", discoveryErrors,
			"fallback_count", len(m.fallbackAddrs))
		return m.fallbackAddrs, fmt.Errorf("all bootstrap discovery methods failed")
	}

	return m.validateAndShuffle(allAddresses), nil
}

// ValidateAndShuffle removes duplicates and invalid addresses and shuffles the
// remaining addresses using a cryptographically secure random number generator
func (m *Manager) validateAndShuffle(addresses []string) []string {
	// Remove duplicates and validate
	uniqueMap := make(map[string]bool)
	validAddresses := make([]string, 0, len(addresses))

	for _, addr := range addresses {
		// Skip if already seen
		if uniqueMap[addr] {
			continue
		}
		uniqueMap[addr] = true

		// Validate the address
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			m.logger.Debug("Invalid bootstrap address format", "address", addr, "error", err)
			continue
		}

		// Check if the host is a valid IP
		if net.ParseIP(host) == nil {
			m.logger.Debug("Bootstrap address is not an IP", "address", addr)
			continue
		}

		// Add to valid addresses
		validAddresses = append(validAddresses, net.JoinHostPort(host, port))
	}

	// Shuffle the addresses securely
	shuffled := make([]string, len(validAddresses))
	copy(shuffled, validAddresses)

	// Fisher-Yates shuffle with crypto/rand
	for i := len(shuffled) - 1; i > 0; i-- {
		// Generate a random number between 0 and i (inclusive)
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			// If secure random fails, don't shuffle - fail securely
			m.logger.Error("Failed to generate secure random number for bootstrap shuffling", "error", err)
			return validAddresses
		}
		shuffled[i], shuffled[j.Int64()] = shuffled[j.Int64()], shuffled[i]
	}

	return shuffled
}

// getValidCacheEntries returns all cache entries that are still valid
func (m *Manager) getValidCacheEntries() []*BootstrapResult {
	var validEntries []*BootstrapResult
	now := time.Now()

	for _, entry := range m.cache {
		if now.Sub(entry.Timestamp) < entry.TTL {
			validEntries = append(validEntries, entry)
		}
	}

	return validEntries
}

// performHealthCheck checks if the bootstrap addresses are reachable
func (m *Manager) performHealthCheck(addresses []string) []string {
	if len(addresses) == 0 {
		return addresses
	}

	timeout := m.healthCheck.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}

	concurrency := m.healthCheck.Concurrency
	if concurrency <= 0 {
		concurrency = 5
	}

	m.logger.Debug("Performing bootstrap health checks",
		"addresses", len(addresses),
		"timeout", timeout,
		"concurrency", concurrency)

	var healthyAddresses []string
	var mutex sync.Mutex
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, concurrency)

	for _, addr := range addresses {
		wg.Add(1)
		semaphore <- struct{}{} // Acquire semaphore

		go func(addr string) {
			defer wg.Done()
			defer func() { <-semaphore }() // Release semaphore

			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err != nil {
				m.logger.Debug("Bootstrap address failed health check", "address", addr, "error", err)
				return
			}
			defer func() { _ = conn.Close() }()

			mutex.Lock()
			healthyAddresses = append(healthyAddresses, addr)
			mutex.Unlock()
		}(addr)
	}

	wg.Wait()

	m.logger.Info("Bootstrap health check complete",
		"total", len(addresses),
		"healthy", len(healthyAddresses))

	return healthyAddresses
}

// InitializeIPPool creates and initializes the IP pool with the given configuration
func (m *Manager) InitializeIPPool(config IPPoolConfig) error {
	pool := &IPPool{
		addresses:       make(map[string]time.Time),
		maxSize:         config.MaxSize,
		minSize:         config.MinSize,
		mutex:           &sync.RWMutex{},
		logger:          m.logger,
		persistPath:     config.PersistPath,
		refreshInterval: config.RefreshInterval,
	}

	// Set default values if not provided
	if pool.maxSize <= 0 {
		pool.maxSize = 1000
	}
	if pool.minSize <= 0 {
		pool.minSize = 10
	}
	if pool.refreshInterval == 0 {
		pool.refreshInterval = 24 * time.Hour
	}

	// Try to load saved addresses
	if pool.persistPath != "" {
		if err := pool.LoadFromFile(); err != nil {
			m.logger.Warn("Could not load saved IP pool", "error", err)
			// Continue even if load fails
		}
	}

	m.ipPool = pool
	return nil
}

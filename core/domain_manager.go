package core

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/pkg/logging"
)

const (
	// DefaultMaxRetries is the default number of times to try connecting to a domain
	DefaultMaxRetries = 3

	// DefaultMinSuccessRate is the minimum success rate for a domain to be considered healthy
	DefaultMinSuccessRate = 0.7

	// DefaultDomainTTL is the time a domain health status is valid before rechecking
	DefaultDomainTTL = 1 * time.Hour

	// DefaultDomainCacheSize is the default number of domains to keep in the cache
	DefaultDomainCacheSize = 100
)

// DomainStatus represents the current status of a domain
type DomainStatus string

const (
	// DomainStatusUnknown indicates the domain has not been checked yet
	DomainStatusUnknown DomainStatus = "unknown"

	// DomainStatusHealthy indicates the domain is reachable and working correctly
	DomainStatusHealthy DomainStatus = "healthy"

	// DomainStatusUnhealthy indicates the domain is not reachable or not working correctly
	DomainStatusUnhealthy DomainStatus = "unhealthy"

	// DomainStatusBlocked indicates the domain appears to be blocked
	DomainStatusBlocked DomainStatus = "blocked"
)

// DomainHealth tracks the health status of a domain
type DomainHealth struct {
	Domain       string       // The domain name
	Status       DomainStatus // Current status of the domain
	SuccessRate  float64      // Rate of successful connections (0.0-1.0)
	LastChecked  time.Time    // When the domain was last checked
	CheckCount   int          // Number of times the domain has been checked
	SuccessCount int          // Number of successful connections
	FailureCount int          // Number of failed connections
	TimePeriod   int64        // The time period this domain was generated for
}

// DomainManagerConfig holds the configuration for the DomainManager
type DomainManagerConfig struct {
	// DGA is the domain generation algorithm configuration
	DGA *config.DGAConfig

	// TimeSynchronizer provides accurate time for domain generation
	TimeSynchronizer *TimeSynchronizer

	// MaxRetries is the maximum number of times to try connecting to a domain
	MaxRetries int

	// MinSuccessRate is the minimum success rate for a domain to be considered healthy
	MinSuccessRate float64

	// DomainTTL is how long a domain health status is valid before rechecking
	DomainTTL time.Duration

	// DomainCacheSize is the maximum number of domains to keep in the cache
	DomainCacheSize int

	// LookbackPeriods is the number of past time periods to include in domain generation
	LookbackPeriods int

	// LookaheadPeriods is the number of future time periods to include in domain generation
	LookaheadPeriods int

	// DomainsPerPeriod is the number of domains to generate for each time period
	DomainsPerPeriod int

	// Logger is the logger to use for logging
	Logger logging.Logger
}

// NewDomainManagerConfig creates a new domain manager configuration with defaults
func NewDomainManagerConfig() *DomainManagerConfig {
	return &DomainManagerConfig{
		MaxRetries:       DefaultMaxRetries,
		MinSuccessRate:   DefaultMinSuccessRate,
		DomainTTL:        DefaultDomainTTL,
		DomainCacheSize:  DefaultDomainCacheSize,
		LookbackPeriods:  1,
		LookaheadPeriods: 1,
		DomainsPerPeriod: 3,
	}
}

// DomainManager manages domain rotation and health tracking
type DomainManager struct {
	config *DomainManagerConfig
	dga    *DomainGenerationAlgorithm
	health map[string]*DomainHealth
	mutex  sync.RWMutex
	logger logging.Logger
}

// NewDomainManager creates a new domain manager
func NewDomainManager(config *DomainManagerConfig) (*DomainManager, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	if config.DGA == nil {
		return nil, errors.New("DGA config cannot be nil")
	}

	if config.TimeSynchronizer == nil {
		return nil, errors.New("TimeSynchronizer cannot be nil")
	}

	if config.Logger == nil {
		config.Logger = logging.GetLogger()
	}

	dga, err := NewDomainGenerationAlgorithm(config.DGA, config.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to create DGA: %w", err)
	}

	return &DomainManager{
		config: config,
		dga:    dga,
		health: make(map[string]*DomainHealth),
		mutex:  sync.RWMutex{},
		logger: config.Logger,
	}, nil
}

// GetCurrentTimePeriod returns the current time period based on the time synchronizer
func (dm *DomainManager) GetCurrentTimePeriod() (int64, error) {
	currentTime := dm.config.TimeSynchronizer.GetCurrentTime()
	quantizedTime := dm.config.TimeSynchronizer.GetQuantizedTime()

	dm.logger.Debug("Current time: %v, quantized time: %v", currentTime, quantizedTime)

	return quantizedTime.Unix(), nil
}

// GetDomainsForCurrentPeriod returns domains for the current time period
func (dm *DomainManager) GetDomainsForCurrentPeriod() ([]string, error) {
	timePeriod, err := dm.GetCurrentTimePeriod()
	if err != nil {
		return nil, err
	}

	return dm.GetDomainsForPeriod(timePeriod)
}

// GetDomainsForPeriod returns domains for the specified time period
func (dm *DomainManager) GetDomainsForPeriod(timePeriod int64) ([]string, error) {
	dm.logger.Debug("Generating domains for time period: %d", timePeriod)

	// Convert Unix timestamp to time.Time
	periodTime := time.Unix(timePeriod, 0)

	// Generate domains using the DGA
	domains, err := dm.dga.GenerateDomainsForPeriod(periodTime, dm.config.DomainsPerPeriod)
	if err != nil {
		return nil, fmt.Errorf("failed to generate domains for period %d: %w", timePeriod, err)
	}

	// Initialize health status for new domains
	dm.initializeDomainsHealth(domains, timePeriod)

	return domains, nil
}

// GetAllManagedDomains returns all domains for current, past, and future time periods
func (dm *DomainManager) GetAllManagedDomains() ([]string, error) {
	timeWindows, err := dm.getTimeWindows()
	if err != nil {
		return nil, err
	}

	var allDomains []string

	// Generate domains for each time window
	for _, windowTime := range timeWindows {
		domains, err := dm.dga.GenerateDomainsForPeriod(windowTime, dm.config.DomainsPerPeriod)
		if err != nil {
			dm.logger.Warn("Failed to generate domains for time window %v: %v", windowTime, err)
			continue
		}

		// Initialize health status for new domains
		dm.initializeDomainsHealth(domains, windowTime.Unix())

		allDomains = append(allDomains, domains...)
	}

	return allDomains, nil
}

// GetNextDomain returns the next healthy domain to use
func (dm *DomainManager) GetNextDomain() (string, error) {
	domains, err := dm.GetAllManagedDomains()
	if err != nil {
		return "", err
	}

	if len(domains) == 0 {
		return "", errors.New("no domains available")
	}

	// First try to find a known healthy domain
	for _, domain := range domains {
		if dm.isDomainHealthy(domain) {
			dm.logger.Debug("Using known healthy domain: %s", domain)
			return domain, nil
		}
	}

	// If no healthy domains found, try domains with unknown status
	for _, domain := range domains {
		if dm.getDomainStatus(domain) == DomainStatusUnknown {
			dm.logger.Debug("Using domain with unknown status: %s", domain)
			return domain, nil
		}
	}

	// If no healthy or unknown domains found, use the first domain
	dm.logger.Warn("No healthy domains found, using first available: %s", domains[0])
	return domains[0], nil
}

// ReportDomainSuccess reports a successful connection to a domain
func (dm *DomainManager) ReportDomainSuccess(domain string) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	health, exists := dm.health[domain]
	if !exists {
		// Create new health entry if it doesn't exist
		health = &DomainHealth{
			Domain:       domain,
			Status:       DomainStatusUnknown,
			SuccessRate:  1.0, // Start with full success rate
			LastChecked:  time.Now(),
			CheckCount:   1,
			SuccessCount: 1,
			FailureCount: 0,
		}
		dm.health[domain] = health
	} else {
		// Update existing health entry
		health.CheckCount++
		health.SuccessCount++
		health.SuccessRate = float64(health.SuccessCount) / float64(health.CheckCount)
		health.LastChecked = time.Now()
	}

	// Update status based on success rate
	if health.SuccessRate >= dm.config.MinSuccessRate {
		health.Status = DomainStatusHealthy
	} else {
		health.Status = DomainStatusUnhealthy
	}

	dm.logger.Debug("Domain %s health updated: status=%s, success_rate=%.2f",
		domain, health.Status, health.SuccessRate)
}

// ReportDomainFailure reports a failed connection to a domain
func (dm *DomainManager) ReportDomainFailure(domain string) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	health, exists := dm.health[domain]
	if !exists {
		// Create new health entry if it doesn't exist
		health = &DomainHealth{
			Domain:       domain,
			Status:       DomainStatusUnhealthy, // Start as unhealthy
			SuccessRate:  0.0,
			LastChecked:  time.Now(),
			CheckCount:   1,
			SuccessCount: 0,
			FailureCount: 1,
		}
		dm.health[domain] = health
	} else {
		// Update existing health entry
		health.CheckCount++
		health.FailureCount++
		health.SuccessRate = float64(health.SuccessCount) / float64(health.CheckCount)
		health.LastChecked = time.Now()
	}

	// Update status based on success rate
	if health.SuccessRate < dm.config.MinSuccessRate {
		health.Status = DomainStatusUnhealthy

		// Mark as blocked if we've tried multiple times and never succeeded
		if health.CheckCount >= dm.config.MaxRetries && health.SuccessCount == 0 {
			health.Status = DomainStatusBlocked
			dm.logger.Warn("Domain %s appears to be blocked after %d failures",
				domain, health.FailureCount)
		}
	}

	dm.logger.Debug("Domain %s health updated: status=%s, success_rate=%.2f",
		domain, health.Status, health.SuccessRate)
}

// CleanupExpiredDomains removes expired domains from the health cache
func (dm *DomainManager) CleanupExpiredDomains() {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	now := time.Now()

	// Find expired domains
	var expiredDomains []string
	for domain, health := range dm.health {
		if now.Sub(health.LastChecked) > dm.config.DomainTTL {
			expiredDomains = append(expiredDomains, domain)
		}
	}

	// Remove expired domains
	for _, domain := range expiredDomains {
		dm.logger.Debug("Removing expired domain from cache: %s", domain)
		delete(dm.health, domain)
	}

	// If we have too many domains in the cache, remove the oldest ones
	if len(dm.health) > dm.config.DomainCacheSize {
		// Find the oldest domains
		type domainAge struct {
			domain string
			age    time.Time
		}

		var domains []domainAge
		for domain, health := range dm.health {
			domains = append(domains, domainAge{domain, health.LastChecked})
		}

		// Sort domains by last checked time (oldest first)
		for i := 0; i < len(domains); i++ {
			for j := i + 1; j < len(domains); j++ {
				if domains[i].age.After(domains[j].age) {
					domains[i], domains[j] = domains[j], domains[i]
				}
			}
		}

		// Remove oldest domains until we're under the cache size limit
		for i := 0; i < len(domains) && len(dm.health) > dm.config.DomainCacheSize; i++ {
			dm.logger.Debug("Removing oldest domain from cache: %s", domains[i].domain)
			delete(dm.health, domains[i].domain)
		}
	}
}

// GetDomainHealth returns the health status of a domain
func (dm *DomainManager) GetDomainHealth(domain string) *DomainHealth {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	if health, exists := dm.health[domain]; exists {
		return health
	}

	return nil
}

// GetHealthyDomains returns all currently healthy domains
func (dm *DomainManager) GetHealthyDomains() []string {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	var healthyDomains []string

	for domain, health := range dm.health {
		if health.Status == DomainStatusHealthy &&
			time.Since(health.LastChecked) <= dm.config.DomainTTL {
			healthyDomains = append(healthyDomains, domain)
		}
	}

	return healthyDomains
}

// Private helper methods

// initializeDomainsHealth initializes health status for new domains
func (dm *DomainManager) initializeDomainsHealth(domains []string, timePeriod int64) {
	dm.mutex.Lock()
	defer dm.mutex.Unlock()

	for _, domain := range domains {
		if _, exists := dm.health[domain]; !exists {
			dm.health[domain] = &DomainHealth{
				Domain:      domain,
				Status:      DomainStatusUnknown,
				LastChecked: time.Now(),
				TimePeriod:  timePeriod,
			}
		}
	}
}

// isDomainHealthy checks if a domain is considered healthy
func (dm *DomainManager) isDomainHealthy(domain string) bool {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	health, exists := dm.health[domain]
	if !exists {
		return false
	}

	// Consider a domain healthy if:
	// 1. It has a healthy status
	// 2. The status is not expired
	// 3. Success rate is above minimum
	return health.Status == DomainStatusHealthy &&
		time.Since(health.LastChecked) <= dm.config.DomainTTL &&
		health.SuccessRate >= dm.config.MinSuccessRate
}

// getDomainStatus returns the current status of a domain
func (dm *DomainManager) getDomainStatus(domain string) DomainStatus {
	dm.mutex.RLock()
	defer dm.mutex.RUnlock()

	if health, exists := dm.health[domain]; exists {
		return health.Status
	}

	return DomainStatusUnknown
}

// getTimeWindows returns time windows for domain generation including past, present, and future periods
func (dm *DomainManager) getTimeWindows() ([]time.Time, error) {
	currentPeriod, err := dm.GetCurrentTimePeriod()
	if err != nil {
		return nil, err
	}

	currentTime := time.Unix(currentPeriod, 0)
	rotationTime := time.Duration(dm.dga.config.RotationTime) * time.Second

	// Calculate time windows
	windows := make([]time.Time, 1+dm.config.LookbackPeriods+dm.config.LookaheadPeriods)

	// Add current window
	windows[dm.config.LookbackPeriods] = currentTime

	// Add past windows
	for i := 1; i <= dm.config.LookbackPeriods; i++ {
		windows[dm.config.LookbackPeriods-i] = currentTime.Add(-time.Duration(i) * rotationTime)
	}

	// Add future windows
	for i := 1; i <= dm.config.LookaheadPeriods; i++ {
		windows[dm.config.LookbackPeriods+i] = currentTime.Add(time.Duration(i) * rotationTime)
	}

	return windows, nil
}

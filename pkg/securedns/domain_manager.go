package securedns

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
)

// DomainStatus represents the health status of a domain
type DomainStatus int

const (
	// DomainStatusUnknown indicates the domain hasn't been tested yet
	DomainStatusUnknown DomainStatus = iota
	// DomainStatusHealthy indicates the domain is accessible
	DomainStatusHealthy
	// DomainStatusUnhealthy indicates the domain is not accessible
	DomainStatusUnhealthy
	// DomainStatusBlocked indicates the domain appears to be blocked
	DomainStatusBlocked
)

// DomainGenerator defines the interface for domain generation
type DomainGenerator interface {
	// GetDomainsForPeriod generates domains for a specific time period
	GetDomainsForPeriod(period time.Time, count int) ([]string, error)
}

// DomainInfo stores information about a generated domain
type DomainInfo struct {
	Domain       string
	Status       DomainStatus
	LastTested   time.Time
	IPs          []net.IP
	FailCount    int
	SuccessCount int
}

// RotationConfig contains configuration for the domain rotation manager
type RotationConfig struct {
	// MaxDomains is the maximum number of domains to keep in the pool
	MaxDomains int
	// HealthCheckInterval is how often to check domain health
	HealthCheckInterval time.Duration
	// RotationInterval is how often to rotate to a new domain
	RotationInterval time.Duration
	// UnhealthyThreshold is the number of failures before marking a domain unhealthy
	UnhealthyThreshold int
	// BlockedThreshold is the number of specific failures that indicate blocking
	BlockedThreshold int
	// ConnectionTimeout is the timeout for connection attempts
	ConnectionTimeout time.Duration
	// RotationJitter adds randomness to rotation timing to prevent synchronized behavior
	RotationJitter float64
	// NumDomainsPerPeriod is how many domains to generate for each time period
	NumDomainsPerPeriod int
	// NumTimePeriods is the number of time periods to generate domains for (current, future, past)
	NumTimePeriods int
}

// TimeSynchronizerInterface defines the interface for time synchronization
type TimeSynchronizerInterface interface {
	// GetAccurateTime returns the current time, synchronized with NTP if possible
	GetAccurateTime() (time.Time, error)
	// QuantizeTime rounds a timestamp to the nearest quantization interval
	QuantizeTime(t time.Time) time.Time
	// GetQuantizationInterval returns the current quantization interval
	GetQuantizationInterval() time.Duration
}

// DomainRotationManager handles rotating through generated domains
type DomainRotationManager struct {
	mu               sync.RWMutex
	dga              DomainGenerator
	config           *RotationConfig
	domains          map[string]*DomainInfo
	activeDomain     string
	lastRotation     time.Time
	timeSynchronizer TimeSynchronizerInterface
	healthChecker    *healthChecker
	logger           logging.Logger
	resolver         Resolver
	stopChan         chan struct{}
	wg               sync.WaitGroup
}

// NewDomainRotationManager creates a new domain rotation manager
func NewDomainRotationManager(dga DomainGenerator, resolver Resolver, timeSynchronizer TimeSynchronizerInterface, config *RotationConfig, logger logging.Logger) (*DomainRotationManager, error) {
	if dga == nil {
		return nil, fmt.Errorf("domain generation algorithm cannot be nil")
	}

	if resolver == nil {
		return nil, fmt.Errorf("resolver cannot be nil")
	}

	if timeSynchronizer == nil {
		return nil, fmt.Errorf("time synchronizer cannot be nil")
	}

	if config == nil {
		config = &RotationConfig{
			MaxDomains:          50,
			HealthCheckInterval: 5 * time.Minute,
			RotationInterval:    1 * time.Hour,
			UnhealthyThreshold:  3,
			BlockedThreshold:    5,
			ConnectionTimeout:   30 * time.Second,
			RotationJitter:      0.2, // 20% jitter
			NumDomainsPerPeriod: 10,
			NumTimePeriods:      3,
		}
	}

	if logger == nil {
		logger = logging.GetLogger()
	}

	logger = logger.With("component", "domain-manager")

	healthChecker := &healthChecker{
		resolver:          resolver,
		connectionTimeout: config.ConnectionTimeout,
		logger:            logger.With("subcomponent", "health-checker"),
	}

	mgr := &DomainRotationManager{
		dga:              dga,
		config:           config,
		domains:          make(map[string]*DomainInfo),
		lastRotation:     time.Now(),
		timeSynchronizer: timeSynchronizer,
		healthChecker:    healthChecker,
		logger:           logger,
		resolver:         resolver,
		stopChan:         make(chan struct{}),
	}

	return mgr, nil
}

// Start initializes the domain pool and starts background tasks
func (m *DomainRotationManager) Start(ctx context.Context) error {
	// Initialize domain pool
	if err := m.initializeDomainPool(ctx); err != nil {
		return fmt.Errorf("failed to initialize domain pool: %w", err)
	}

	// Select initial active domain
	if err := m.selectActiveDomain(ctx); err != nil {
		return fmt.Errorf("failed to select active domain: %w", err)
	}

	// Start background tasks
	m.startBackgroundTasks()

	return nil
}

// Stop halts all background tasks
func (m *DomainRotationManager) Stop() {
	close(m.stopChan)
	m.wg.Wait()
}

// GetActiveDomain returns the current active domain
func (m *DomainRotationManager) GetActiveDomain() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.activeDomain
}

// GetDomainInfo returns information about a specific domain
func (m *DomainRotationManager) GetDomainInfo(domain string) (*DomainInfo, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	info, exists := m.domains[domain]
	return info, exists
}

// GetHealthyDomains returns a list of all healthy domains
func (m *DomainRotationManager) GetHealthyDomains() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var healthyDomains []string
	for domain, info := range m.domains {
		if info.Status == DomainStatusHealthy {
			healthyDomains = append(healthyDomains, domain)
		}
	}

	return healthyDomains
}

// RotateToNextDomain forces rotation to the next healthy domain
func (m *DomainRotationManager) RotateToNextDomain(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.rotateToNextDomainLocked(ctx)
}

// initializeDomainPool generates the initial set of domains
func (m *DomainRotationManager) initializeDomainPool(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.logger.Info("Initializing domain pool")

	// Get current time window from the time synchronizer
	currentTime, err := m.timeSynchronizer.GetAccurateTime()
	if err != nil {
		return fmt.Errorf("failed to get accurate time: %w", err)
	}

	// Calculate the current period
	currentPeriod := m.timeSynchronizer.QuantizeTime(currentTime)

	// Calculate how many periods we need before and after the current period
	// We want to distribute periods evenly around the current period
	totalPeriods := m.config.NumTimePeriods

	// Always include the current period
	periods := []time.Time{currentPeriod}

	// Add past and future periods symmetrically
	for i := 1; i < totalPeriods; i++ {
		if i%2 == 1 {
			// Odd indices: add a past period
			pastPeriod := currentPeriod.Add(-time.Duration(i/2+1) * m.timeSynchronizer.GetQuantizationInterval())
			periods = append(periods, pastPeriod)
		} else {
			// Even indices: add a future period
			futurePeriod := currentPeriod.Add(time.Duration(i/2) * m.timeSynchronizer.GetQuantizationInterval())
			periods = append(periods, futurePeriod)
		}
	}

	m.logger.Info("Generating domains for periods", "count", len(periods))

	// Generate domains for each time period
	for _, timePeriod := range periods {
		domains, err := m.dga.GetDomainsForPeriod(timePeriod, m.config.NumDomainsPerPeriod)
		if err != nil {
			return fmt.Errorf("failed to generate domains for period %v: %w", timePeriod, err)
		}

		// Add domains to the pool
		for _, domain := range domains {
			m.domains[domain] = &DomainInfo{
				Domain:     domain,
				Status:     DomainStatusUnknown,
				LastTested: time.Time{}, // Zero time
			}
		}
	}

	m.logger.Info("Domain pool initialized", "count", len(m.domains))
	return nil
}

// selectActiveDomain chooses a domain to be active
func (m *DomainRotationManager) selectActiveDomain(ctx context.Context) error {
	// Note: This function expects the caller to hold the lock already
	// Do not acquire the lock again here to avoid deadlock

	if len(m.domains) == 0 {
		return fmt.Errorf("no domains available in the pool")
	}

	// First try to find a healthy domain
	var candidates []string
	for domain, info := range m.domains {
		if info.Status == DomainStatusHealthy {
			candidates = append(candidates, domain)
		}
	}

	// If no healthy domains, try unknown domains
	if len(candidates) == 0 {
		for domain, info := range m.domains {
			if info.Status == DomainStatusUnknown {
				candidates = append(candidates, domain)
			}
		}
	}

	// If still no candidates, use any non-blocked domain
	if len(candidates) == 0 {
		for domain, info := range m.domains {
			if info.Status != DomainStatusBlocked {
				candidates = append(candidates, domain)
			}
		}
	}

	// If still no candidates, use any domain as a last resort
	if len(candidates) == 0 {
		for domain := range m.domains {
			candidates = append(candidates, domain)
		}
	}

	// Randomly select a candidate
	if len(candidates) > 0 {
		idx, err := secureRandomInt(len(candidates))
		if err != nil {
			return fmt.Errorf("failed to generate secure random index: %w", err)
		}

		selectedDomain := candidates[idx]
		m.activeDomain = selectedDomain
		m.lastRotation = time.Now()

		m.logger.Info("Selected active domain", "domain", selectedDomain, "status", m.domains[selectedDomain].Status)

		// If the domain is untested, schedule an immediate health check
		if m.domains[selectedDomain].Status == DomainStatusUnknown {
			go m.checkDomainHealth(ctx, selectedDomain)
		}

		return nil
	}

	return fmt.Errorf("no suitable domains found in the pool")
}

// rotateToNextDomainLocked rotates to the next domain (must be called with lock held)
func (m *DomainRotationManager) rotateToNextDomainLocked(ctx context.Context) error {
	// Select a new active domain (previous one is still a candidate but will likely not be chosen
	// if there are other healthy domains available)
	return m.selectActiveDomain(ctx)
}

// startBackgroundTasks starts the health check and rotation tasks
func (m *DomainRotationManager) startBackgroundTasks() {
	m.wg.Add(2)

	// Start health check task
	go func() {
		defer m.wg.Done()
		healthCheckTicker := time.NewTicker(m.config.HealthCheckInterval)
		defer healthCheckTicker.Stop()

		for {
			select {
			case <-healthCheckTicker.C:
				m.runHealthChecks(context.Background())
			case <-m.stopChan:
				return
			}
		}
	}()

	// Start domain rotation task
	go func() {
		defer m.wg.Done()

		// Add jitter to the first rotation
		jitterDuration := time.Duration(float64(m.config.RotationInterval) * m.config.RotationJitter)
		initialDelay := m.config.RotationInterval

		// Generate secure random jitter
		jitterFloat, err := secureRandomFloat()
		if err == nil {
			initialDelay += time.Duration(float64(jitterDuration) * jitterFloat)
		}

		rotationTimer := time.NewTimer(initialDelay)

		for {
			select {
			case <-rotationTimer.C:
				ctx := context.Background()
				if err := m.RotateToNextDomain(ctx); err != nil {
					m.logger.Error("Failed to rotate to next domain", "error", err)
				}

				// Apply jitter to the next rotation
				nextDelay := m.config.RotationInterval

				// Generate secure random jitter
				jitterFloat, err := secureRandomFloat()
				if err == nil {
					nextDelay += time.Duration(float64(jitterDuration) * (jitterFloat*2 - 1))
				}

				rotationTimer.Reset(nextDelay)
			case <-m.stopChan:
				if !rotationTimer.Stop() {
					<-rotationTimer.C
				}
				return
			}
		}
	}()
}

// runHealthChecks performs health checks on all domains
func (m *DomainRotationManager) runHealthChecks(ctx context.Context) {
	m.mu.RLock()
	domains := make([]string, 0, len(m.domains))
	for domain := range m.domains {
		domains = append(domains, domain)
	}
	m.mu.RUnlock()

	for _, domain := range domains {
		go m.checkDomainHealth(ctx, domain)
	}
}

// checkDomainHealth checks if a domain is accessible
func (m *DomainRotationManager) checkDomainHealth(ctx context.Context, domain string) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(ctx, m.config.ConnectionTimeout)
	defer cancel()

	m.logger.Debug("Checking domain health", "domain", domain)

	// Check domain health
	ips, err := m.healthChecker.checkDomain(ctx, domain)

	m.mu.Lock()
	defer m.mu.Unlock()

	// Get domain info, skip if domain no longer exists
	info, exists := m.domains[domain]
	if !exists {
		return
	}

	info.LastTested = time.Now()

	if err != nil {
		info.FailCount++
		m.logger.Debug("Domain health check failed", "domain", domain, "error", err, "failCount", info.FailCount)

		// Check for blocked pattern
		if m.healthChecker.isBlockedError(err) && info.FailCount >= m.config.BlockedThreshold {
			info.Status = DomainStatusBlocked
			m.logger.Warn("Domain appears to be blocked", "domain", domain)
		} else if info.FailCount >= m.config.UnhealthyThreshold {
			info.Status = DomainStatusUnhealthy
			m.logger.Warn("Domain marked as unhealthy", "domain", domain)
		}

		// If active domain is unhealthy, schedule rotation
		if domain == m.activeDomain && (info.Status == DomainStatusUnhealthy || info.Status == DomainStatusBlocked) {
			go func() {
				ctx := context.Background()
				if err := m.RotateToNextDomain(ctx); err != nil {
					m.logger.Error("Failed to rotate from unhealthy domain", "error", err)
				}
			}()
		}
	} else {
		info.SuccessCount++
		info.FailCount = 0 // Reset fail count on success
		info.Status = DomainStatusHealthy
		info.IPs = ips
		m.logger.Debug("Domain health check succeeded", "domain", domain, "ips", ips)
	}
}

// healthChecker performs health checks on domains
type healthChecker struct {
	resolver          Resolver
	connectionTimeout time.Duration
	logger            logging.Logger
}

// checkDomain verifies if a domain is accessible
func (h *healthChecker) checkDomain(ctx context.Context, domain string) ([]net.IP, error) {
	// Try to resolve the domain using the secure resolver
	ips, err := h.resolver.LookupIP(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve domain: %w", err)
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPs found for domain")
	}

	// For a more thorough check, we could try to establish a connection to the domain
	// on common ports, but that's beyond the scope of this implementation

	return ips, nil
}

// isBlockedError attempts to determine if an error indicates domain blocking
func (h *healthChecker) isBlockedError(err error) bool {
	// This is a simplified check
	// A more sophisticated implementation would look for patterns that indicate
	// intentional blocking, such as:
	// - DNS responses with NXDOMAIN for known-good domains
	// - DNS responses that redirect to known block pages
	// - Consistent timeouts across multiple domains

	return false
}

// secureRandomInt generates a secure random integer between 0 and max-1
func secureRandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("max must be positive")
	}

	maxBig := big.NewInt(int64(max))
	n, err := rand.Int(rand.Reader, maxBig)
	if err != nil {
		return 0, err
	}

	return int(n.Int64()), nil
}

// secureRandomFloat generates a secure random float between 0 and 1
func secureRandomFloat() (float64, error) {
	// Generate a random integer between 0 and 2^53-1 (to maintain floating-point precision)
	maxBig := big.NewInt(1)
	maxBig.Lsh(maxBig, 53)
	n, err := rand.Int(rand.Reader, maxBig)
	if err != nil {
		return 0, err
	}

	// Convert to float64 and divide by 2^53 to get a value between 0 and 1
	return float64(n.Int64()) / float64(maxBig.Int64()), nil
}

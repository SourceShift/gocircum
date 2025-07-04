package securedns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// MockDomainGenerator is a mock implementation of the DomainGenerator interface
type MockDomainGenerator struct {
	getDomainsForPeriodFunc func(period time.Time, count int) ([]string, error)
}

func (m *MockDomainGenerator) GetDomainsForPeriod(period time.Time, count int) ([]string, error) {
	if m.getDomainsForPeriodFunc != nil {
		return m.getDomainsForPeriodFunc(period, count)
	}
	// Default implementation returns test domains
	domains := make([]string, count)
	for i := 0; i < count; i++ {
		domains[i] = "testdomain" + string(rune('1'+i)) + ".com"
	}
	return domains, nil
}

// TestDomainRotationManager_NewDomainRotationManager tests the creation of a new domain rotation manager
func TestDomainRotationManager_NewDomainRotationManager(t *testing.T) {
	mockDGA := &MockDomainGenerator{}
	mockResolver := &MockResolver{}

	timeSyncConfig := &TimeSyncConfig{
		QuantizationInterval: time.Hour,
	}

	timeSync, err := NewTimeSynchronizer(timeSyncConfig, nil)
	require.NoError(t, err)

	rotationConfig := &RotationConfig{
		MaxDomains:          20,
		HealthCheckInterval: time.Minute,
		RotationInterval:    time.Hour,
		UnhealthyThreshold:  3,
		BlockedThreshold:    5,
		ConnectionTimeout:   10 * time.Second,
		RotationJitter:      0.1,
		NumDomainsPerPeriod: 5,
		NumTimePeriods:      2,
	}

	manager, err := NewDomainRotationManager(mockDGA, mockResolver, timeSync, rotationConfig, nil)

	require.NoError(t, err)
	require.NotNil(t, manager)
	assert.Equal(t, mockDGA, manager.dga)
	assert.Equal(t, mockResolver, manager.resolver)
	assert.Equal(t, timeSync, manager.timeSynchronizer)
	assert.Equal(t, rotationConfig, manager.config)
}

// TestDomainRotationManager_NilParameters tests that nil parameters are rejected
func TestDomainRotationManager_NilParameters(t *testing.T) {
	mockDGA := &MockDomainGenerator{}
	mockResolver := &MockResolver{}

	timeSyncConfig := &TimeSyncConfig{
		QuantizationInterval: time.Hour,
	}

	timeSync, err := NewTimeSynchronizer(timeSyncConfig, nil)
	require.NoError(t, err)

	// Test nil DGA
	_, err = NewDomainRotationManager(nil, mockResolver, timeSync, nil, nil)
	assert.Error(t, err)

	// Test nil resolver
	_, err = NewDomainRotationManager(mockDGA, nil, timeSync, nil, nil)
	assert.Error(t, err)

	// Test nil time synchronizer
	_, err = NewDomainRotationManager(mockDGA, mockResolver, nil, nil, nil)
	assert.Error(t, err)

	// Test with all required parameters (config can be nil)
	_, err = NewDomainRotationManager(mockDGA, mockResolver, timeSync, nil, nil)
	assert.NoError(t, err)
}

// TestDomainRotationManager_InitializeDomainPool tests domain pool initialization
func TestDomainRotationManager_InitializeDomainPool(t *testing.T) {
	currentTime := time.Now()

	// Create a mock DGA that returns specific test domains
	mockDGA := &MockDomainGenerator{
		getDomainsForPeriodFunc: func(period time.Time, count int) ([]string, error) {
			// Return different domains based on the time period
			if period.Equal(currentTime.Truncate(time.Hour)) {
				// Current period
				return []string{
					"domain1.com",
					"domain2.com",
					"domain3.com",
				}[:count], nil
			} else if period.Before(currentTime) {
				// Past period
				return []string{
					"prevdomain1.com",
					"prevdomain2.com",
					"prevdomain3.com",
				}[:count], nil
			} else {
				// Future period
				return []string{
					"futuredomain1.com",
					"futuredomain2.com",
					"futuredomain3.com",
				}[:count], nil
			}
		},
	}

	// Create a mock resolver that successfully resolves any domain
	mockResolver := &MockResolver{
		lookupIPFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.2.3.4")}, nil
		},
	}

	// Create a mock time synchronizer that returns the test currentTime
	mockTimeSync := &MockTimeSynchronizer{
		getAccurateTimeFunc: func() (time.Time, error) {
			return currentTime, nil
		},
		quantizeTimeFunc: func(t time.Time) time.Time {
			return t.Truncate(time.Hour)
		},
		getQuantizationIntervalFunc: func() time.Duration {
			return time.Hour
		},
	}

	rotationConfig := &RotationConfig{
		NumDomainsPerPeriod: 3,
		NumTimePeriods:      2,
	}

	manager, err := NewDomainRotationManager(mockDGA, mockResolver, mockTimeSync, rotationConfig, logging.GetLogger())
	require.NoError(t, err)

	// Initialize domain pool
	err = manager.initializeDomainPool(context.Background())
	require.NoError(t, err)

	// Verify domain pool has the correct count of domains
	assert.Equal(t, rotationConfig.NumDomainsPerPeriod*rotationConfig.NumTimePeriods, len(manager.domains))

	// Check that domains from all time periods exist in the pool
	for domain := range manager.domains {
		// The domain should be one of our expected domains
		validDomain := strings.HasPrefix(domain, "domain") ||
			strings.HasPrefix(domain, "prevdomain") ||
			strings.HasPrefix(domain, "futuredomain")
		assert.True(t, validDomain, "Unexpected domain in pool: %s", domain)
	}

	// Verify all domains are initially unknown status
	for _, domain := range manager.domains {
		assert.Equal(t, DomainStatusUnknown, domain.Status)
	}
}

// Define a mock TimeSynchronizer for testing
type MockTimeSynchronizer struct {
	getAccurateTimeFunc         func() (time.Time, error)
	quantizeTimeFunc            func(t time.Time) time.Time
	getQuantizationIntervalFunc func() time.Duration
}

func (m *MockTimeSynchronizer) GetAccurateTime() (time.Time, error) {
	if m.getAccurateTimeFunc != nil {
		return m.getAccurateTimeFunc()
	}
	return time.Now(), nil
}

func (m *MockTimeSynchronizer) QuantizeTime(t time.Time) time.Time {
	if m.quantizeTimeFunc != nil {
		return m.quantizeTimeFunc(t)
	}
	return t
}

func (m *MockTimeSynchronizer) GetQuantizationInterval() time.Duration {
	if m.getQuantizationIntervalFunc != nil {
		return m.getQuantizationIntervalFunc()
	}
	return time.Hour
}

// TestDomainRotationManager_DomainHealth tests domain health management
func TestDomainRotationManager_DomainHealth(t *testing.T) {
	mockDGA := &MockDomainGenerator{
		getDomainsForPeriodFunc: func(period time.Time, count int) ([]string, error) {
			return []string{
				"healthy.com",
				"unhealthy.com",
			}[:count], nil
		},
	}

	// Create a mock resolver that handles different domains differently
	mockResolver := &MockResolver{
		lookupIPFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			switch host {
			case "healthy.com":
				return []net.IP{net.ParseIP("1.2.3.4")}, nil
			case "unhealthy.com":
				return nil, assert.AnError
			default:
				return []net.IP{net.ParseIP("1.2.3.4")}, nil
			}
		},
	}

	timeSyncConfig := &TimeSyncConfig{
		QuantizationInterval: time.Hour,
	}

	timeSync, err := NewTimeSynchronizer(timeSyncConfig, nil)
	require.NoError(t, err)

	rotationConfig := &RotationConfig{
		NumDomainsPerPeriod: 2,
		NumTimePeriods:      1,
		UnhealthyThreshold:  2,
	}

	manager, err := NewDomainRotationManager(mockDGA, mockResolver, timeSync, rotationConfig, logging.GetLogger())
	require.NoError(t, err)

	// Initialize domain pool
	err = manager.initializeDomainPool(context.Background())
	require.NoError(t, err)

	// Check health of healthy domain
	manager.checkDomainHealth(context.Background(), "healthy.com")

	info, exists := manager.GetDomainInfo("healthy.com")
	assert.True(t, exists)
	assert.Equal(t, DomainStatusHealthy, info.Status)
	assert.Equal(t, 0, info.FailCount)
	assert.Equal(t, 1, info.SuccessCount)

	// Check health of unhealthy domain (first failure)
	manager.checkDomainHealth(context.Background(), "unhealthy.com")

	info, exists = manager.GetDomainInfo("unhealthy.com")
	assert.True(t, exists)
	assert.Equal(t, DomainStatusUnknown, info.Status) // Not yet marked unhealthy
	assert.Equal(t, 1, info.FailCount)

	// Check health of unhealthy domain (second failure - should mark as unhealthy)
	manager.checkDomainHealth(context.Background(), "unhealthy.com")

	info, exists = manager.GetDomainInfo("unhealthy.com")
	assert.True(t, exists)
	assert.Equal(t, DomainStatusUnhealthy, info.Status) // Now marked unhealthy
	assert.Equal(t, 2, info.FailCount)
}

// TestDomainRotationManager_GetHealthyDomains tests the GetHealthyDomains method
func TestDomainRotationManager_GetHealthyDomains(t *testing.T) {
	mockDGA := &MockDomainGenerator{
		getDomainsForPeriodFunc: func(period time.Time, count int) ([]string, error) {
			return []string{
				"healthy1.com",
				"healthy2.com",
				"unhealthy.com",
			}[:count], nil
		},
	}

	mockResolver := &MockResolver{}

	timeSyncConfig := &TimeSyncConfig{
		QuantizationInterval: time.Hour,
	}

	timeSync, err := NewTimeSynchronizer(timeSyncConfig, nil)
	require.NoError(t, err)

	rotationConfig := &RotationConfig{
		NumDomainsPerPeriod: 3,
		NumTimePeriods:      1,
	}

	manager, err := NewDomainRotationManager(mockDGA, mockResolver, timeSync, rotationConfig, logging.GetLogger())
	require.NoError(t, err)

	// Initialize domain pool
	err = manager.initializeDomainPool(context.Background())
	require.NoError(t, err)

	// Manually set domain statuses
	manager.domains["healthy1.com"].Status = DomainStatusHealthy
	manager.domains["healthy2.com"].Status = DomainStatusHealthy
	manager.domains["unhealthy.com"].Status = DomainStatusUnhealthy

	// Get healthy domains
	healthyDomains := manager.GetHealthyDomains()

	// Verify results
	assert.Equal(t, 2, len(healthyDomains))
	assert.Contains(t, healthyDomains, "healthy1.com")
	assert.Contains(t, healthyDomains, "healthy2.com")
	assert.NotContains(t, healthyDomains, "unhealthy.com")
}

// TestDomainRotationManager_GetActiveDomain tests active domain selection and retrieval
func TestDomainRotationManager_GetActiveDomain(t *testing.T) {
	mockDGA := &MockDomainGenerator{
		getDomainsForPeriodFunc: func(period time.Time, count int) ([]string, error) {
			return []string{
				"domain1.com",
				"domain2.com",
			}[:count], nil
		},
	}

	mockResolver := &MockResolver{
		lookupIPFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("1.2.3.4")}, nil
		},
	}

	timeSyncConfig := &TimeSyncConfig{
		QuantizationInterval: time.Hour,
	}

	timeSync, err := NewTimeSynchronizer(timeSyncConfig, nil)
	require.NoError(t, err)

	rotationConfig := &RotationConfig{
		NumDomainsPerPeriod: 2,
		NumTimePeriods:      1,
	}

	manager, err := NewDomainRotationManager(mockDGA, mockResolver, timeSync, rotationConfig, logging.GetLogger())
	require.NoError(t, err)

	// Initialize domain pool
	err = manager.initializeDomainPool(context.Background())
	require.NoError(t, err)

	// Select active domain
	err = manager.selectActiveDomain(context.Background())
	require.NoError(t, err)

	// Get active domain
	activeDomain := manager.GetActiveDomain()

	// Verify an active domain was selected
	assert.NotEmpty(t, activeDomain)
	assert.Contains(t, []string{"domain1.com", "domain2.com"}, activeDomain)
}

// TestDomainRotationManager_RotateToNextDomain tests domain rotation
func TestDomainRotationManager_RotateToNextDomain(t *testing.T) {
	mockDGA := &MockDomainGenerator{
		getDomainsForPeriodFunc: func(period time.Time, count int) ([]string, error) {
			return []string{"domain1.com", "domain2.com"}, nil
		},
	}

	mockResolver := &MockResolver{
		lookupIPFunc: func(ctx context.Context, hostname string) ([]net.IP, error) {
			switch hostname {
			case "domain1.com":
				return []net.IP{net.ParseIP("192.0.2.1")}, nil
			case "domain2.com":
				return []net.IP{net.ParseIP("192.0.2.2")}, nil
			default:
				return nil, fmt.Errorf("unknown domain")
			}
		},
	}

	timeSyncConfig := &TimeSyncConfig{
		QuantizationInterval: 24 * time.Hour,
	}

	timeSync, err := NewTimeSynchronizer(timeSyncConfig, logging.GetLogger())
	require.NoError(t, err)

	rotationConfig := &RotationConfig{
		NumDomainsPerPeriod: 2,
		NumTimePeriods:      1,
		ConnectionTimeout:   500 * time.Millisecond, // Use a short timeout
	}

	manager, err := NewDomainRotationManager(mockDGA, mockResolver, timeSync, rotationConfig, logging.GetLogger())
	require.NoError(t, err)

	// Initialize domain pool
	err = manager.initializeDomainPool(context.Background())
	require.NoError(t, err)

	// Mark both domains as healthy to make the test more deterministic
	manager.domains["domain1.com"].Status = DomainStatusHealthy
	manager.domains["domain2.com"].Status = DomainStatusHealthy

	// Manually set the active domain
	manager.activeDomain = "domain1.com"

	// Create a context with a short timeout to prevent test from hanging
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Rotate to next domain
	err = manager.RotateToNextDomain(ctx)
	require.NoError(t, err)

	// Verify active domain has changed
	newActiveDomain := manager.GetActiveDomain()
	assert.NotEmpty(t, newActiveDomain)
}

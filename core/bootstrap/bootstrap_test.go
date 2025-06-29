package bootstrap

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger implements a simple logger for tests
type testLogger struct{}

func (l *testLogger) Debug(msg string, keysAndValues ...interface{}) {}
func (l *testLogger) Info(msg string, keysAndValues ...interface{})  {}
func (l *testLogger) Warn(msg string, keysAndValues ...interface{})  {}
func (l *testLogger) Error(msg string, keysAndValues ...interface{}) {}
func (l *testLogger) With(keysAndValues ...interface{}) logging.Logger {
	return l
}

func TestNewManager(t *testing.T) {
	logger := &testLogger{}

	// Test with nil logger
	manager, err := NewManager(BootstrapConfig{}, nil)
	assert.Error(t, err)
	assert.Nil(t, manager)

	// Test with valid logger
	manager, err = NewManager(BootstrapConfig{}, logger)
	assert.NoError(t, err)
	assert.NotNil(t, manager)
}

func TestManagerRegisterProvider(t *testing.T) {
	logger := &testLogger{}
	config := BootstrapConfig{
		HealthCheck:       HealthCheckOptions{},
		FallbackAddresses: []string{"1.2.3.4:443"},
	}

	manager, err := NewManager(config, logger)
	require.NoError(t, err, "Failed to create Manager")

	// Register a test provider
	provider := &mockProvider{
		name:      "test_provider",
		priority:  10,
		addresses: []string{"1.2.3.4:443"},
	}
	manager.RegisterProvider(provider)

	// Override createEmergencyFallbackPhase for testing
	manager.createEmergencyFallbackPhaseFunc = func() DecentralizedDiscoveryPhase {
		return &testEmergencyFallbackPhase{
			addresses: provider.addresses,
		}
	}

	// Call DiscoverBootstraps and verify results
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	addresses, err := manager.DiscoverBootstraps(ctx)
	require.NoError(t, err, "Failed to discover bootstraps")
	require.Equal(t, []string{"1.2.3.4:443"}, addresses, "Did not receive expected addresses")
}

// testEmergencyFallbackPhase is a test implementation of DecentralizedDiscoveryPhase
type testEmergencyFallbackPhase struct {
	addresses []string
}

func (t *testEmergencyFallbackPhase) GetName() string {
	return "test_emergency_fallback"
}

func (t *testEmergencyFallbackPhase) ExecuteWithConsensus(ctx context.Context, network *DecentralizedNetwork) ConsensusResult {
	return ConsensusResult{
		Source:            t.GetName(),
		Addresses:         t.addresses,
		ConsensusStrength: 1.0,
		ParticipantCount:  1,
		Timestamp:         time.Now(),
	}
}

func (t *testEmergencyFallbackPhase) ValidateResults(addresses []string) error {
	return nil
}

func TestLoadConfiguration(t *testing.T) {
	// Create a temporary test configuration file
	tmpDir, err := os.MkdirTemp("", "bootstrap-test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	configPath := filepath.Join(tmpDir, "config.yaml")
	configContent := `
health_check:
  enabled: true
  timeout: 2s
  concurrency: 5
fallback_addresses:
  - "1.1.1.1:443"
  - "8.8.8.8:443"
providers:
  - type: "doh"
    enabled: true
    priority: 100
`

	err = os.WriteFile(configPath, []byte(configContent), 0644)
	require.NoError(t, err)

	// Test loading the configuration
	config, err := LoadConfiguration(configPath)
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.True(t, config.HealthCheck.Enabled)
	assert.Equal(t, 2*time.Second, config.HealthCheck.Timeout)
	assert.Equal(t, 5, config.HealthCheck.Concurrency)
	assert.Equal(t, 2, len(config.FallbackAddresses))
	assert.Equal(t, "1.1.1.1:443", config.FallbackAddresses[0])
	assert.Equal(t, 1, len(config.Providers))
	assert.Equal(t, "doh", config.Providers[0].Type)
}

func TestIPPoolBasics(t *testing.T) {
	logger := &testLogger{}

	// Create a temporary directory for persistence
	tmpDir, err := os.MkdirTemp("", "ippool-test")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	persistPath := filepath.Join(tmpDir, "ippool.json")

	// Create a pool with configuration
	pool := &IPPool{
		addresses:       make(map[string]time.Time),
		maxSize:         10,
		minSize:         3,
		mutex:           &sync.RWMutex{},
		logger:          logger,
		persistPath:     persistPath,
		refreshInterval: time.Hour,
	}

	// Add some addresses
	addresses := []string{
		"1.1.1.1:443",
		"2.2.2.2:443",
		"3.3.3.3:443",
		"4.4.4.4:443",
	}

	pool.AddAddresses(addresses)

	// Check that addresses were added
	poolAddresses := pool.GetAddresses()
	assert.Equal(t, len(addresses), len(poolAddresses))
	for _, addr := range addresses {
		found := false
		for _, poolAddr := range poolAddresses {
			if poolAddr == addr {
				found = true
				break
			}
		}
		assert.True(t, found, "Address %s should be in the pool", addr)
	}

	// Check NeedsRefresh
	assert.False(t, pool.NeedsRefresh())

	// Test persistence
	err = pool.SaveToFile()
	assert.NoError(t, err)

	// Create a new pool and load from file
	pool2 := &IPPool{
		addresses:       make(map[string]time.Time),
		maxSize:         10,
		minSize:         3,
		mutex:           &sync.RWMutex{},
		logger:          logger,
		persistPath:     persistPath,
		refreshInterval: time.Hour,
	}

	err = pool2.LoadFromFile()
	assert.NoError(t, err)

	// Check that addresses were loaded
	pool2Addresses := pool2.GetAddresses()
	assert.Equal(t, len(addresses), len(pool2Addresses))
}

// mockProvider implements BootstrapProvider for testing
type mockProvider struct {
	name      string
	addresses []string
	priority  int
	err       error
}

func (p *mockProvider) Name() string {
	return p.name
}

func (p *mockProvider) Discover(ctx context.Context) ([]string, error) {
	if p.err != nil {
		return nil, p.err
	}
	return p.addresses, nil
}

func (p *mockProvider) Priority() int {
	return p.priority
}

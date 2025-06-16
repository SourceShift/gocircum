package bridge_test

import (
	"context"
	"gocircum/core/config"
	"gocircum/interfaces"
	"gocircum/mobile/bridge"
	"gocircum/testutils"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

// MockStatusUpdater captures status updates for testing.
type MockStatusUpdater struct {
	mu       sync.Mutex
	statuses []string
	messages []string
}

func (m *MockStatusUpdater) OnStatusUpdate(status, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses = append(m.statuses, status)
	m.messages = append(m.messages, message)
}

func (m *MockStatusUpdater) LastStatus() (string, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.statuses) == 0 {
		return "", ""
	}
	return m.statuses[len(m.statuses)-1], m.messages[len(m.messages)-1]
}

func TestStartEngine_DynamicConfig(t *testing.T) {
	// This test requires a running mock echo server.
	server := testutils.NewMockTLSEchoServer()
	defer server.Close()

	// Since we are testing the global bridge, we need to ensure it's clean.
	bridge.SetGlobalBridgeForTesting(nil)

	// Create a valid YAML config string.
	validConfig := config.FileConfig{
		Fingerprints: []config.Fingerprint{
			{
				ID:          "test-tcp",
				Description: "Test TCP strategy",
				Transport:   config.Transport{Protocol: "tcp"},
				TLS:         config.TLS{Library: "stdlib", SkipVerify: true, MinVersion: "1.2", MaxVersion: "1.3"}, // Skip verify for mock server
			},
		},
	}
	yamlBytes, err := yaml.Marshal(validConfig)
	assert.NoError(t, err)

	updater := &MockStatusUpdater{}

	// We need to run StartEngine in a goroutine because it's blocking.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		bridge.StartEngine(string(yamlBytes), updater)
	}()

	// Give the engine time to start.
	assert.Eventually(t, func() bool {
		status, _ := updater.LastStatus()
		return status == "CONNECTED"
	}, testutils.TestTimeout, testutils.TestInterval)

	// Verify we can connect to the proxy.
	err = testutils.CheckSOCKS5Proxy("127.0.0.1:1080", server.Addr())
	assert.NoError(t, err, "SOCKS5 proxy check should succeed")

	// Stop the engine.
	bridge.StopEngine(updater)
	wg.Wait() // Wait for the start goroutine to finish.

	status, msg := updater.LastStatus()
	assert.Equal(t, "DISCONNECTED", status)
	assert.Equal(t, "Engine stopped.", msg)
}

func TestStartEngine_EmptyConfig(t *testing.T) {
	bridge.SetGlobalBridgeForTesting(nil)
	updater := &MockStatusUpdater{}
	bridge.StartEngine("", updater)

	status, msg := updater.LastStatus()
	assert.Equal(t, "ERROR", status)
	assert.Contains(t, msg, "configuration is empty")
}

func TestStartEngine_InvalidYAML(t *testing.T) {
	bridge.SetGlobalBridgeForTesting(nil)
	updater := &MockStatusUpdater{}
	bridge.StartEngine("not: valid: yaml", updater)

	status, msg := updater.LastStatus()
	assert.Equal(t, "ERROR", status)
	assert.Contains(t, msg, "failed to parse configuration")
}

func TestStartEngine_NoStrategies(t *testing.T) {
	bridge.SetGlobalBridgeForTesting(nil)
	updater := &MockStatusUpdater{}
	bridge.StartEngine("fingerprints: []", updater)

	status, msg := updater.LastStatus()
	assert.Equal(t, "ERROR", status)
	assert.Contains(t, msg, "no strategies found")
}

// MockEngine demonstrates how to create a mock for testing.
type MockEngine struct {
	interfaces.Engine
	StartProxyErr error
}

func (m *MockEngine) StartProxyWithStrategy(ctx context.Context, addr string, fp *config.Fingerprint) error {
	return m.StartProxyErr
}

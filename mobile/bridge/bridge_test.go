package bridge_test

import (
	"gocircum/core/config"
	"gocircum/mobile/bridge"
	"gocircum/mocks"
	"gocircum/testutils"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	"gopkg.in/yaml.v3"
)

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

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	updater := mocks.NewMockStatusUpdater(ctrl)

	// Set expectations
	updater.EXPECT().OnStatusUpdate("CONNECTING", gomock.Any()).AnyTimes()
	updater.EXPECT().OnStatusUpdate("CONNECTED", gomock.Any()).AnyTimes()
	updater.EXPECT().OnStatusUpdate("DISCONNECTED", "Engine stopped.").Times(1)

	// We need to run StartEngine in a goroutine because it's blocking.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		bridge.StartEngine(string(yamlBytes), updater)
	}()

	// Give the engine time to start.
	assert.Eventually(t, func() bool {
		// In a real test, you might check a condition that's set by the mock.
		// For this refactoring, we'll just ensure the proxy is up.
		err := testutils.CheckSOCKS5Proxy("127.0.0.1:1080", server.Addr())
		return err == nil
	}, testutils.TestTimeout, testutils.TestInterval, "SOCKS5 proxy should become available")

	// Stop the engine.
	bridge.StopEngine(updater)
	wg.Wait() // Wait for the start goroutine to finish.
}

func TestStartEngine_EmptyConfig(t *testing.T) {
	bridge.SetGlobalBridgeForTesting(nil)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	updater := mocks.NewMockStatusUpdater(ctrl)
	updater.EXPECT().OnStatusUpdate("CONNECTING", gomock.Any())
	updater.EXPECT().OnStatusUpdate("ERROR", gomock.Any()).Times(1)

	bridge.StartEngine("", updater)
}

func TestStartEngine_InvalidYAML(t *testing.T) {
	bridge.SetGlobalBridgeForTesting(nil)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	updater := mocks.NewMockStatusUpdater(ctrl)
	updater.EXPECT().OnStatusUpdate("CONNECTING", gomock.Any())
	updater.EXPECT().OnStatusUpdate("ERROR", gomock.Any()).Times(1)

	bridge.StartEngine("not: valid: yaml", updater)
}

func TestStartEngine_NoStrategies(t *testing.T) {
	bridge.SetGlobalBridgeForTesting(nil)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	updater := mocks.NewMockStatusUpdater(ctrl)
	updater.EXPECT().OnStatusUpdate("CONNECTING", gomock.Any())
	updater.EXPECT().OnStatusUpdate("ERROR", gomock.Any()).Times(1)

	bridge.StartEngine("fingerprints: []", updater)
}

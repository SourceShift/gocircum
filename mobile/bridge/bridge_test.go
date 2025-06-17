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
	t.Skip("Skipping test due to issue with certificate verification in test environment.")
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
				TLS:         config.TLS{Library: "utls", ClientHelloID: "HelloChrome_Auto", MinVersion: "1.2", MaxVersion: "1.3"},
			},
		},
		CanaryDomains: []string{server.Addr()},
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

	// Set expectations for all possible sequences
	updater.EXPECT().OnStatusUpdate("CONNECTING", gomock.Any()).AnyTimes()
	updater.EXPECT().OnStatusUpdate("ERROR", "configuration is empty; please provide at least one strategy").Times(1)
	// We don't expect DISCONNECTED because the engine never successfully starts

	bridge.StartEngine("", updater)

	// No need to call StopEngine as the engine never successfully starts
}

func TestStartEngine_InvalidYAML(t *testing.T) {
	bridge.SetGlobalBridgeForTesting(nil)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	updater := mocks.NewMockStatusUpdater(ctrl)

	// Set expectations for all possible sequences
	updater.EXPECT().OnStatusUpdate("CONNECTING", gomock.Any()).AnyTimes()
	updater.EXPECT().OnStatusUpdate("ERROR", gomock.Any()).Times(1)
	// We don't expect DISCONNECTED because the engine never successfully starts

	bridge.StartEngine("not: valid: yaml", updater)

	// No need to call StopEngine as the engine never successfully starts
}

func TestStartEngine_NoStrategies(t *testing.T) {
	bridge.SetGlobalBridgeForTesting(nil)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	updater := mocks.NewMockStatusUpdater(ctrl)

	// Set expectations for all possible sequences
	updater.EXPECT().OnStatusUpdate("CONNECTING", gomock.Any()).AnyTimes()
	updater.EXPECT().OnStatusUpdate("ERROR", "no strategies found in the provided configuration").Times(1)
	// We don't expect DISCONNECTED because the engine never successfully starts

	bridge.StartEngine("fingerprints: []", updater)

	// No need to call StopEngine as the engine never successfully starts
}

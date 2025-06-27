package gocircum_test

import (
	"context"
	"os"
	"testing"

	"github.com/gocircum/gocircum"
	"github.com/gocircum/gocircum/core/config"
	"gopkg.in/yaml.v3"
)

// loadTestConfig loads a simple YAML config file for testing without security validation
func loadTestConfig(filePath string) (*config.FileConfig, error) {
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	
	var cfg config.FileConfig
	if err := yaml.Unmarshal(buf, &cfg); err != nil {
		return nil, err
	}
	
	return &cfg, nil
}

func TestEngineLifecycle(t *testing.T) {
	if _, err := os.Stat("test_strategies.yaml"); os.IsNotExist(err) {
		t.Skip("test_strategies.yaml not found, skipping lifecycle test.")
	}

	cfg, err := loadTestConfig("test_strategies.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	engine, err := gocircum.NewEngine(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Use the first available fingerprint from the config for the lifecycle test.
	// The actual functionality of the strategy is tested elsewhere.
	if len(cfg.Fingerprints) == 0 {
		t.Fatal("No fingerprints found in test_strategies.yaml")
	}
	strategy := &cfg.Fingerprints[0]

	// The start function uses the best strategy, which requires a real network connection.
	// This makes it an integration test, not a unit test.
	// For now, we'll just check that it doesn't return an immediate error.
	// A proper integration test would require a test server.
	addr, err := engine.StartProxyWithStrategy(context.Background(), "127.0.0.1:0", strategy)
	if err != nil {
		t.Fatalf("Engine failed to start: %v", err)
	}

	status, err := engine.Status()
	if err != nil {
		t.Fatalf("Failed to get engine status: %v", err)
	}
	expectedStatus := "Proxy running on " + addr
	if status != expectedStatus {
		t.Errorf("Expected status '%s', got '%s'", expectedStatus, status)
	}

	if err := engine.Stop(); err != nil {
		t.Errorf("Engine failed to stop: %v", err)
	}
}

func TestCanBeImported(t *testing.T) {
	// This test primarily exists to be run by an external project.
	// For now, we just ensure we can create the engine.
	if _, err := os.Stat("test_strategies.yaml"); os.IsNotExist(err) {
		t.Skip("test_strategies.yaml not found, skipping import test.")
	}
	cfg, err := loadTestConfig("test_strategies.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	_, err = gocircum.NewEngine(cfg, nil)
	if err != nil {
		t.Fatalf("gocircum library could not be initialized in a test context: %v", err)
	}
	t.Log("Successfully imported and initialized gocircum library.")
}

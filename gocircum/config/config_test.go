package config_test

import (
	"gocircum/config"
	"testing"
)

func TestLoadValidConfig(t *testing.T) {
	cfg, err := config.LoadConfig("testdata/valid_config.yaml")
	if err != nil {
		t.Fatalf("Failed to load valid config: %v", err)
	}

	if len(cfg.Strategies) != 2 {
		t.Errorf("Expected 2 strategies, got %d", len(cfg.Strategies))
	}

	if cfg.Strategies[0].Name != "chrome_utls_tcp" {
		t.Errorf("Expected first strategy name to be 'chrome_utls_tcp', got '%s'", cfg.Strategies[0].Name)
	}

	if !cfg.Strategies[0].Enabled {
		t.Error("Expected first strategy to be enabled")
	}

	if cfg.Strategies[0].Transport.Protocol != "tcp" {
		t.Errorf("Expected first strategy transport protocol to be 'tcp', got '%s'", cfg.Strategies[0].Transport.Protocol)
	}

	if len(cfg.Strategies[0].Middleware) != 1 {
		t.Errorf("Expected 1 middleware, got %d", len(cfg.Strategies[0].Middleware))
	}
}

func TestLoadInvalidConfigs(t *testing.T) {
	testCases := []struct {
		name     string
		path     string
		expError string
	}{
		{
			name:     "Missing Name",
			path:     "testdata/invalid_missing_name.yaml",
			expError: "strategy 0 is missing a name",
		},
		{
			name:     "Invalid Protocol",
			path:     "testdata/invalid_protocol.yaml",
			expError: "strategy 'bad_protocol' has an invalid transport protocol: udp",
		},
		{
			name:     "File Not Found",
			path:     "testdata/non_existent_file.yaml",
			expError: "failed to read config file",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := config.LoadConfig(tc.path)
			if err == nil {
				t.Fatalf("Expected an error but got none")
			}
			if !contains(err.Error(), tc.expError) {
				t.Errorf("Expected error to contain '%s', got '%v'", tc.expError, err)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr || len(s) > len(substr) && s[:len(substr)] == substr
}

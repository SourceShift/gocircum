package gocircum_test

import (
	"context"
	"gocircum"
	"gocircum/core/config"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestEngineLifecycle(t *testing.T) {
	// --- Setup mock HTTP server ---
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "HTTP/1.1 200 OK\r\n\r\nHello")
	}))
	defer server.Close()

	if _, err := os.Stat("test_strategies.yaml"); os.IsNotExist(err) {
		t.Skip("test_strategies.yaml not found, skipping lifecycle test.")
	}

	cfg, err := config.LoadFileConfig("test_strategies.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}

	// --- Override config for test ---
	serverHost, _, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to parse server address: %v", err)
	}

	// Point to the mock server instead of a real canary. Use the full address.
	cfg.CanaryDomains = []string{server.Listener.Addr().String()}

	// Provide a dummy DoH provider to satisfy validation. It won't be used
	// because the canary domain is an IP address.
	cfg.DoHProviders = []config.DoHProvider{
		{Name: "dummy", URL: "https://1.2.3.4/dns-query", ServerName: "dummy.com", Bootstrap: []string{"1.2.3.4"}},
	}

	// We must also update the fingerprint to use the test server's host
	// for domain fronting to ensure the SNI matches, and to skip verification
	// of the self-signed certificate.
	for i := range cfg.Fingerprints {
		if cfg.Fingerprints[i].DomainFronting != nil {
			cfg.Fingerprints[i].DomainFronting.FrontDomain = serverHost
		}
		cfg.Fingerprints[i].TLS.InsecureSkipVerify = true
	}

	engine, err := gocircum.NewEngine(cfg, nil)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	best, err := engine.GetBestStrategy(context.Background())
	if err != nil {
		t.Fatalf("Expected GetBestStrategy to succeed, but it failed: %v", err)
	}

	// The start function uses the best strategy, which requires a real network connection.
	// This makes it an integration test, not a unit test.
	// For now, we'll just check that it doesn't return an immediate error.
	// A proper integration test would require a test server.
	addr, err := engine.StartProxyWithStrategy(context.Background(), "127.0.0.1:0", best)
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
	cfg, err := config.LoadFileConfig("test_strategies.yaml")
	if err != nil {
		t.Fatalf("Failed to load test config: %v", err)
	}
	_, err = gocircum.NewEngine(cfg, nil)
	if err != nil {
		t.Fatalf("gocircum library could not be initialized in a test context: %v", err)
	}
	t.Log("Successfully imported and initialized gocircum library.")
}

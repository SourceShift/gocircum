//go:build integration
// +build integration

package securedns

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// This file contains integration tests for the secure DNS resolver.
// These tests verify that the resolver works correctly in a real environment.
// Run these tests with: go test -tags=integration ./pkg/securedns

// TestRealDoHProviders tests that the resolver can connect to real DoH providers.
func TestRealDoHProviders(t *testing.T) {
	resolver, err := New(nil)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer resolver.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	domains := []string{
		"example.com",
		"google.com",
		"cloudflare.com",
	}

	for _, domain := range domains {
		ips, err := resolver.LookupIP(ctx, domain)
		if err != nil {
			t.Errorf("Failed to resolve %s: %v", domain, err)
			continue
		}

		if len(ips) == 0 {
			t.Errorf("No IPs returned for %s", domain)
			continue
		}

		t.Logf("Successfully resolved %s to %v", domain, ips)
	}
}

// TestSecureHTTPClientIntegration tests that the secure HTTP client works correctly.
func TestSecureHTTPClientIntegration(t *testing.T) {
	resolver, err := New(nil)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer resolver.Close()

	client := NewSecureHTTPClient(resolver)

	// Test with a real website
	resp, err := client.Get("https://example.com")
	if err != nil {
		t.Fatalf("Failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d %s", resp.StatusCode, resp.Status)
	}
}

// TestNoSystemDNSUsage tests that the resolver doesn't use the system DNS.
// This test requires a network sniffer to be running to verify no DNS queries are made.
// The test itself doesn't verify this, but it provides a way to manually verify.
func TestNoSystemDNSUsage(t *testing.T) {
	t.Log("This test requires a network sniffer (like Wireshark or tcpdump) to be running")
	t.Log("to verify that no DNS queries are made to the system resolver.")
	t.Log("Command to monitor DNS: sudo tcpdump -n udp port 53 or tcp port 53")

	resolver, err := New(nil)
	if err != nil {
		t.Fatalf("Failed to create resolver: %v", err)
	}
	defer resolver.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// This domain should not trigger a system DNS query
	t.Log("Resolving example.com - check your sniffer for DNS queries...")
	time.Sleep(1 * time.Second) // Give time to start monitoring

	_, err = resolver.LookupIP(ctx, "example.com")
	if err != nil {
		t.Fatalf("Failed to resolve example.com: %v", err)
	}

	time.Sleep(2 * time.Second) // Give time to observe any queries
	t.Log("Resolution complete. If no DNS queries were observed, the test passed.")
}

// TestCustomBootstrapIPs tests that the resolver can be configured with custom bootstrap IPs.
func TestCustomBootstrapIPs(t *testing.T) {
	// Create a custom configuration with specific bootstrap IPs
	config := &SecureConfig{
		DoH: &BootstrapConfig{
			BootstrapIPs: map[string][]net.IP{
				"dns.cloudflare.com": {
					net.ParseIP("1.1.1.1"),
					net.ParseIP("1.0.0.1"),
				},
			},
			TrustedProviders: []string{
				"dns.cloudflare.com",
			},
		},
		CacheSize:     100,
		CacheTTL:      5 * time.Minute,
		Timeout:       5 * time.Second,
		RetryCount:    2,
		BlockFallback: true,
		UserAgent:     "securedns-integration-test/1.0",
	}

	resolver, err := New(config)
	if err != nil {
		t.Fatalf("Failed to create resolver with custom config: %v", err)
	}
	defer resolver.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := resolver.LookupIP(ctx, "example.com")
	if err != nil {
		t.Fatalf("Failed to resolve example.com with custom bootstrap IPs: %v", err)
	}

	if len(ips) == 0 {
		t.Fatal("No IPs returned for example.com with custom bootstrap IPs")
	}

	t.Logf("Successfully resolved example.com to %v using custom bootstrap IPs", ips)
}

// TestSecureDialerWithHTTPServer tests that the secure dialer works correctly
// by setting up a local HTTP server and connecting to it.
func TestSecureDialerWithHTTPServer(t *testing.T) {
	// Create a simple HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Hello, secure world!"))
	}))
	defer server.Close()

	// Extract the hostname and port from the server URL
	serverURL := server.URL[7:] // Remove "http://"

	// Create a mock resolver that returns the IP of the test server
	mockResolver := &MockResolver{
		lookupFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			// Parse the host:port format to extract just the host
			hostOnly, _, err := net.SplitHostPort(host)
			if err != nil {
				// If there's no port, use the host as is
				hostOnly = host
			}

			// For the test server's hostname, return its actual IP
			hostOnly, _, _ = net.SplitHostPort(serverURL)
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		},
	}

	// Create a secure dialer with the mock resolver
	dialer := NewSecureDialerWithResolver(mockResolver)

	// Create an HTTP client that uses the secure dialer
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}

	// Make a request to the test server
	resp, err := client.Get("http://" + serverURL)
	if err != nil {
		t.Fatalf("Failed to make request with secure dialer: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200 OK, got %d %s", resp.StatusCode, resp.Status)
	}
}

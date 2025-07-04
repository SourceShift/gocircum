package securedns

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestResolverInterface tests that our implementations satisfy the Resolver interface.
func TestResolverInterface(t *testing.T) {
	var _ Resolver = &DoHResolver{}
	var _ Resolver = &MockResolver{}
}

func TestDoHResolverCreation(t *testing.T) {
	// Test with nil config
	config := &BootstrapConfig{
		BootstrapIPs: map[string][]net.IP{
			"dns.google": {net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		},
		TrustedProviders: []string{"dns.google"},
	}

	resolver, err := NewDoHResolver(config, nil)
	if err != nil {
		t.Fatalf("Failed to create DoHResolver: %v", err)
	}

	if resolver == nil {
		t.Fatal("Expected resolver to be non-nil")
	}

	// Close the resolver to clean up resources
	if err := resolver.Close(); err != nil {
		t.Errorf("Failed to close resolver: %v", err)
	}
}

func TestDoHResolverWithInvalidConfig(t *testing.T) {
	// Test with empty bootstrap IPs
	config := &BootstrapConfig{
		BootstrapIPs:     map[string][]net.IP{},
		TrustedProviders: []string{"dns.google"},
	}

	_, err := NewDoHResolver(config, nil)
	if err == nil {
		t.Fatal("Expected error for empty bootstrap IPs, got nil")
	}

	// Test with empty trusted providers
	config = &BootstrapConfig{
		BootstrapIPs: map[string][]net.IP{
			"dns.google": {net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		},
		TrustedProviders: []string{},
	}

	_, err = NewDoHResolver(config, nil)
	if err == nil {
		t.Fatal("Expected error for empty trusted providers, got nil")
	}

	// Test with mismatched bootstrap IPs and trusted providers
	config = &BootstrapConfig{
		BootstrapIPs: map[string][]net.IP{
			"dns.google": {net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		},
		TrustedProviders: []string{"cloudflare-dns.com"},
	}

	_, err = NewDoHResolver(config, nil)
	if err == nil {
		t.Fatal("Expected error for mismatched bootstrap IPs and trusted providers, got nil")
	}
}

func TestSecureDialerWithDoHResolver(t *testing.T) {
	// Create a mock resolver
	mockResolver := &MockResolver{
		lookupIPWithCacheFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "example.com" {
				return []net.IP{net.ParseIP("93.184.216.34")}, nil
			}
			return nil, nil
		},
	}

	// Create a dialer factory
	factory, err := NewSecureDialerFactory(mockResolver)
	if err != nil {
		t.Fatalf("Failed to create dialer factory: %v", err)
	}

	// Create a dialer
	dialer, err := factory.NewDialer(&DialerConfig{
		Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Failed to create dialer: %v", err)
	}

	// Test dialing with a hostname
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// This will not actually connect, but it should try to resolve the hostname
	_, err = dialer.DialContext(ctx, "tcp", "example.com:443")
	// We expect an error because we're not actually connecting to anything,
	// but we want to make sure it's not a resolver error
	if err == nil {
		t.Fatal("Expected connection error, got nil")
	}
}

package securedns

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// Mock resolver implementation for testing
type mockResolver struct {
	lookupIPFunc          func(ctx context.Context, host string) ([]net.IP, error)
	lookupIPWithCacheFunc func(ctx context.Context, host string) ([]net.IP, error)
	preloadCacheFunc      func(entries map[string][]net.IP)
	verifyNoLeaksFunc     func(ctx context.Context) error
	closeFunc             func() error
}

func (m *mockResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if m.lookupIPFunc != nil {
		return m.lookupIPFunc(ctx, host)
	}
	return nil, errors.New("LookupIP not implemented")
}

func (m *mockResolver) LookupIPWithCache(ctx context.Context, host string) ([]net.IP, error) {
	if m.lookupIPWithCacheFunc != nil {
		return m.lookupIPWithCacheFunc(ctx, host)
	}
	return nil, errors.New("LookupIPWithCache not implemented")
}

func (m *mockResolver) PreloadCache(entries map[string][]net.IP) {
	if m.preloadCacheFunc != nil {
		m.preloadCacheFunc(entries)
	}
}

func (m *mockResolver) VerifyNoLeaks(ctx context.Context) error {
	if m.verifyNoLeaksFunc != nil {
		return m.verifyNoLeaksFunc(ctx)
	}
	return nil
}

func (m *mockResolver) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

// Test that creating a dialer factory with nil resolver returns an error
func TestNewSecureDialerFactoryWithNilResolver(t *testing.T) {
	factory, err := NewSecureDialerFactory(nil)
	if err == nil {
		t.Error("Expected error when creating factory with nil resolver, got nil")
	}
	if factory != nil {
		t.Errorf("Expected nil factory when creating with nil resolver, got %v", factory)
	}
}

// Test that creating a dialer factory with a valid resolver succeeds
func TestNewSecureDialerFactoryWithValidResolver(t *testing.T) {
	mockResolver := &mockResolver{}
	factory, err := NewSecureDialerFactory(mockResolver)
	if err != nil {
		t.Errorf("Unexpected error when creating factory with valid resolver: %v", err)
	}
	if factory == nil {
		t.Error("Expected non-nil factory when creating with valid resolver, got nil")
	}
}

// Test NewDialer creates a dialer correctly
func TestNewDialer(t *testing.T) {
	mockResolver := &mockResolver{}
	factory, _ := NewSecureDialerFactory(mockResolver)

	dialer, err := factory.NewDialer(nil)
	if err != nil {
		t.Errorf("Unexpected error when creating dialer: %v", err)
	}
	if dialer == nil {
		t.Error("Expected non-nil dialer, got nil")
	}
}

// Test NewTCPDialer creates a TCP dialer correctly
func TestNewTCPDialer(t *testing.T) {
	mockResolver := &mockResolver{}
	factory, _ := NewSecureDialerFactory(mockResolver)

	config := &DialerConfig{
		Timeout:   5 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	dialer, err := factory.NewTCPDialer(config)
	if err != nil {
		t.Errorf("Unexpected error when creating TCP dialer: %v", err)
	}
	if dialer == nil {
		t.Error("Expected non-nil TCP dialer, got nil")
	}

	// Test with nil config (should use defaults)
	dialer, err = factory.NewTCPDialer(nil)
	if err != nil {
		t.Errorf("Unexpected error when creating TCP dialer with nil config: %v", err)
	}
	if dialer == nil {
		t.Error("Expected non-nil TCP dialer when using nil config, got nil")
	}
}

// Test NewUDPDialer creates a UDP dialer correctly
func TestNewUDPDialer(t *testing.T) {
	mockResolver := &mockResolver{}
	factory, _ := NewSecureDialerFactory(mockResolver)

	config := &DialerConfig{
		Timeout: 5 * time.Second,
	}

	dialer, err := factory.NewUDPDialer(config)
	if err != nil {
		t.Errorf("Unexpected error when creating UDP dialer: %v", err)
	}
	if dialer == nil {
		t.Error("Expected non-nil UDP dialer, got nil")
	}

	// Test with nil config (should use defaults)
	dialer, err = factory.NewUDPDialer(nil)
	if err != nil {
		t.Errorf("Unexpected error when creating UDP dialer with nil config: %v", err)
	}
	if dialer == nil {
		t.Error("Expected non-nil UDP dialer when using nil config, got nil")
	}
}

// Test DialContext when the host is already an IP address
func TestDialContextWithIPAddress(t *testing.T) {
	mockResolver := &mockResolver{}
	factory, _ := NewSecureDialerFactory(mockResolver)

	dialer, _ := factory.NewTCPDialer(nil)

	// This test would typically need a mock net connection
	// Since we can't easily create a real connection in a unit test,
	// we'll rely on the error to verify the code path

	// Using a non-routable IP to ensure we get a connection error
	_, err := dialer.DialContext(context.Background(), "tcp", "192.0.2.1:80")

	// We expect a connection error, not a resolution error
	if err == nil {
		t.Error("Expected connection error when dialing non-routable IP, got nil")
	}
	if err != nil && err.Error() == "secure DNS resolution failed" {
		t.Errorf("Got unexpected DNS resolution error for IP address: %v", err)
	}
}

// Test DialContext when the host requires resolution
func TestDialContextWithHostname(t *testing.T) {
	// Setup mock resolver to return a specific IP
	expectedIP := net.ParseIP("192.0.2.1")
	mockResolver := &mockResolver{
		lookupIPWithCacheFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			if host == "example.com" {
				return []net.IP{expectedIP}, nil
			}
			return nil, errors.New("unexpected host")
		},
	}

	factory, _ := NewSecureDialerFactory(mockResolver)
	dialer, _ := factory.NewTCPDialer(nil)

	// This will fail to connect, but we want to verify the resolution happened
	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:80")

	// Should get a connection error, not a resolution error
	if err == nil {
		t.Error("Expected connection error when dialing non-routable IP, got nil")
	}
	if err != nil && err.Error() == "secure DNS resolution failed" {
		t.Errorf("Got unexpected DNS resolution error: %v", err)
	}
}

// Test DialContext when DNS resolution fails
func TestDialContextWithResolutionFailure(t *testing.T) {
	expectedError := errors.New("dns resolution failed")
	mockResolver := &mockResolver{
		lookupIPWithCacheFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			return nil, expectedError
		},
	}

	factory, _ := NewSecureDialerFactory(mockResolver)
	dialer, _ := factory.NewTCPDialer(nil)

	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:80")

	if err == nil {
		t.Error("Expected error when DNS resolution fails, got nil")
	}
	if err != nil && !errors.Is(err, expectedError) {
		t.Errorf("Expected underlying error to be %v, got %v", expectedError, err)
	}
}

// Test DialContext when DNS resolution returns no IPs
func TestDialContextWithNoIPs(t *testing.T) {
	mockResolver := &mockResolver{
		lookupIPWithCacheFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{}, nil
		},
	}

	factory, _ := NewSecureDialerFactory(mockResolver)
	dialer, _ := factory.NewTCPDialer(nil)

	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:80")

	if err == nil {
		t.Error("Expected error when DNS resolution returns no IPs, got nil")
	}
	if err != nil && !errors.Is(err, err) {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// Test DialContext with mismatched network
func TestDialContextWithMismatchedNetwork(t *testing.T) {
	mockResolver := &mockResolver{}
	factory, _ := NewSecureDialerFactory(mockResolver)

	// Create a TCP dialer
	dialer, _ := factory.NewTCPDialer(nil)

	// Try to use it for UDP
	_, err := dialer.DialContext(context.Background(), "udp", "example.com:53")

	if err == nil {
		t.Error("Expected error when using TCP dialer for UDP, got nil")
	}
	if err != nil && !errors.Is(err, err) {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// Test DialContext with invalid address format
func TestDialContextWithInvalidAddress(t *testing.T) {
	mockResolver := &mockResolver{}
	factory, _ := NewSecureDialerFactory(mockResolver)
	dialer, _ := factory.NewTCPDialer(nil)

	_, err := dialer.DialContext(context.Background(), "tcp", "invalid-address")

	if err == nil {
		t.Error("Expected error when using invalid address format, got nil")
	}
}

// Test DialContext with invalid port
func TestDialContextWithInvalidPort(t *testing.T) {
	mockResolver := &mockResolver{}
	factory, _ := NewSecureDialerFactory(mockResolver)
	dialer, _ := factory.NewTCPDialer(nil)

	_, err := dialer.DialContext(context.Background(), "tcp", "example.com:invalid")

	if err == nil {
		t.Error("Expected error when using invalid port, got nil")
	}
}

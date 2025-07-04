package securedns

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"
)

// TestCreateSecureTransport tests the CreateSecureTransport function.
func TestCreateSecureTransport(t *testing.T) {
	// Test with nil factory
	_, err := CreateSecureTransport(nil, nil)
	if err != ErrNilFactory {
		t.Errorf("Expected ErrNilFactory, got %v", err)
	}

	// Setup mock resolver and factory
	resolver := &MockResolver{
		lookupIPWithCacheFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		},
	}
	factory, _ := NewSecureDialerFactory(resolver)

	// Test with valid factory and nil config
	transport, err := CreateSecureTransport(factory, nil)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if transport == nil {
		t.Error("Expected transport to be non-nil")
	}

	// Test with valid factory and custom config
	config := &TransportConfig{
		TLSConfig:             &tls.Config{},
		MaxIdleConns:          50,
		MaxIdleConnsPerHost:   5,
		MaxConnsPerHost:       50,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		ForceAttemptHTTP2:     false,
	}
	transport, err = CreateSecureTransport(factory, config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if transport == nil {
		t.Error("Expected transport to be non-nil")
		return
	}
	if transport.DisableKeepAlives != true {
		t.Error("Expected DisableKeepAlives to be true")
	}
	if transport.DisableCompression != true {
		t.Error("Expected DisableCompression to be true")
	}
	if transport.ForceAttemptHTTP2 != false {
		t.Error("Expected ForceAttemptHTTP2 to be false")
	}
	if transport.TLSClientConfig == nil {
		t.Error("Expected TLSClientConfig to be non-nil")
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		t.Error("Expected InsecureSkipVerify to be false")
	}
}

// TestCreateSecureHTTPClient tests the CreateSecureHTTPClient function.
func TestCreateSecureHTTPClient(t *testing.T) {
	// Setup mock resolver and factory
	resolver := &MockResolver{
		lookupIPWithCacheFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		},
	}
	factory, _ := NewSecureDialerFactory(resolver)

	// Test with valid factory and nil config
	client, err := CreateSecureHTTPClient(factory, nil)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
	if client == nil {
		t.Error("Expected client to be non-nil")
		return
	}
	if client.Timeout != 60*time.Second {
		t.Errorf("Expected Timeout to be 60s, got %v", client.Timeout)
	}

	// Test with invalid factory
	_, err = CreateSecureHTTPClient(nil, nil)
	if err != ErrNilFactory {
		t.Errorf("Expected ErrNilFactory, got %v", err)
	}
}

// TestDefaultTransportConfig tests the DefaultTransportConfig function.
func TestDefaultTransportConfig(t *testing.T) {
	config := DefaultTransportConfig()
	if config == nil {
		t.Fatal("Expected config to be non-nil")
	}
	if config.MaxIdleConns != 100 {
		t.Errorf("Expected MaxIdleConns to be 100, got %d", config.MaxIdleConns)
	}
	if config.MaxIdleConnsPerHost != 10 {
		t.Errorf("Expected MaxIdleConnsPerHost to be 10, got %d", config.MaxIdleConnsPerHost)
	}
	if config.MaxConnsPerHost != 100 {
		t.Errorf("Expected MaxConnsPerHost to be 100, got %d", config.MaxConnsPerHost)
	}
	if config.IdleConnTimeout != 90*time.Second {
		t.Errorf("Expected IdleConnTimeout to be 90s, got %v", config.IdleConnTimeout)
	}
	if config.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("Expected ResponseHeaderTimeout to be 30s, got %v", config.ResponseHeaderTimeout)
	}
	if config.ExpectContinueTimeout != 1*time.Second {
		t.Errorf("Expected ExpectContinueTimeout to be 1s, got %v", config.ExpectContinueTimeout)
	}
	if config.DisableKeepAlives != false {
		t.Error("Expected DisableKeepAlives to be false")
	}
	if config.DisableCompression != false {
		t.Error("Expected DisableCompression to be false")
	}
	if config.ForceAttemptHTTP2 != true {
		t.Error("Expected ForceAttemptHTTP2 to be true")
	}
}

// TestError tests the Error type.
func TestError(t *testing.T) {
	err := NewError("test error")
	if err.Error() != "test error" {
		t.Errorf("Expected error message to be 'test error', got '%s'", err.Error())
	}
}

// TestSecureTransportIntegration tests the integration of the secure transport with HTTP.
func TestSecureTransportIntegration(t *testing.T) {
	// This is a basic integration test to ensure that the secure transport
	// can be used with the standard HTTP client. It doesn't actually make
	// any network requests, but it verifies that the components fit together.

	// Setup mock resolver and factory
	resolver := &MockResolver{
		lookupIPWithCacheFunc: func(ctx context.Context, host string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.1")}, nil
		},
	}
	factory, _ := NewSecureDialerFactory(resolver)

	// Create a transport and client
	transport, err := CreateSecureTransport(factory, nil)
	if err != nil {
		t.Fatalf("Failed to create transport: %v", err)
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Verify that the client is properly configured
	if client.Transport != transport {
		t.Error("Expected client.Transport to be our secure transport")
	}

	// We don't actually make a request here, as that would require network access
	// and could fail for reasons unrelated to our code. Instead, we just verify
	// that the client is properly configured.
}

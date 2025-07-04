package securedns

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// Mock dialer factory for testing
type mockDialerFactory struct {
	newTCPDialerFunc func(config *DialerConfig) (SecureDialer, error)
	closeFunc        func() error
}

func (m *mockDialerFactory) NewDialer(config *DialerConfig) (SecureDialer, error) {
	return m.NewTCPDialer(config)
}

func (m *mockDialerFactory) NewTCPDialer(config *DialerConfig) (SecureDialer, error) {
	if m.newTCPDialerFunc != nil {
		return m.newTCPDialerFunc(config)
	}
	return &mockDialer{}, nil
}

func (m *mockDialerFactory) NewUDPDialer(config *DialerConfig) (SecureDialer, error) {
	return nil, errors.New("UDP dialer not implemented for this test")
}

func (m *mockDialerFactory) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

// Mock dialer for testing
type mockDialer struct{}

func (d *mockDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, errors.New("this is a mock dialer that doesn't create real connections")
}

// Test that creating an HTTP client factory with nil dialer factory returns an error
func TestNewSecureHTTPClientFactoryWithNilDialerFactory(t *testing.T) {
	factory, err := NewSecureHTTPClientFactory(nil)
	if err == nil {
		t.Error("Expected error when creating HTTP factory with nil dialer factory, got nil")
	}
	if factory != nil {
		t.Errorf("Expected nil factory when creating with nil dialer factory, got %v", factory)
	}
}

// Test that creating an HTTP client factory with a valid dialer factory succeeds
func TestNewSecureHTTPClientFactoryWithValidDialerFactory(t *testing.T) {
	mockFactory := &mockDialerFactory{}
	factory, err := NewSecureHTTPClientFactory(mockFactory)
	if err != nil {
		t.Errorf("Unexpected error when creating HTTP factory with valid dialer factory: %v", err)
	}
	if factory == nil {
		t.Error("Expected non-nil HTTP factory when creating with valid dialer factory, got nil")
	}
}

// Test NewHTTPClient creates a client correctly
func TestNewHTTPClient(t *testing.T) {
	mockFactory := &mockDialerFactory{}
	factory, _ := NewSecureHTTPClientFactory(mockFactory)

	client, err := factory.NewHTTPClient(10 * time.Second)
	if err != nil {
		t.Errorf("Unexpected error when creating HTTP client: %v", err)
	}
	if client == nil {
		t.Error("Expected non-nil HTTP client, got nil")
		return
	}

	// Check that the client has the right timeout
	if client.Timeout != 10*time.Second {
		t.Errorf("Expected client timeout to be 10s, got %v", client.Timeout)
	}

	// Check that the transport is set
	if client.Transport == nil {
		t.Error("Expected client transport to be non-nil, got nil")
	}
}

// Test NewHTTPClientWithConfig creates a client correctly
func TestNewHTTPClientWithConfig(t *testing.T) {
	mockFactory := &mockDialerFactory{}
	factory, _ := NewSecureHTTPClientFactory(mockFactory)

	config := &HTTPClientConfig{
		Timeout:             15 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		DisableKeepAlives:   true,
		MaxIdleConns:        50,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     60 * time.Second,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	client, err := factory.NewHTTPClientWithConfig(config)
	if err != nil {
		t.Errorf("Unexpected error when creating HTTP client with config: %v", err)
	}
	if client == nil {
		t.Error("Expected non-nil HTTP client, got nil")
		return
	}

	// Check that the client has the right timeout
	if client.Timeout != 15*time.Second {
		t.Errorf("Expected client timeout to be 15s, got %v", client.Timeout)
	}

	// Check that the transport is set
	if client.Transport == nil {
		t.Error("Expected client transport to be non-nil, got nil")
	}

	// Check transport settings
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Error("Expected transport to be *http.Transport")
		return
	}

	if transport.DisableKeepAlives != true {
		t.Error("Expected DisableKeepAlives to be true")
	}

	if transport.MaxIdleConns != 50 {
		t.Errorf("Expected MaxIdleConns to be 50, got %d", transport.MaxIdleConns)
	}

	if transport.MaxIdleConnsPerHost != 5 {
		t.Errorf("Expected MaxIdleConnsPerHost to be 5, got %d", transport.MaxIdleConnsPerHost)
	}

	if transport.IdleConnTimeout != 60*time.Second {
		t.Errorf("Expected IdleConnTimeout to be 60s, got %v", transport.IdleConnTimeout)
	}

	if transport.TLSHandshakeTimeout != 5*time.Second {
		t.Errorf("Expected TLSHandshakeTimeout to be 5s, got %v", transport.TLSHandshakeTimeout)
	}
}

// Test NewHTTPClientWithConfig with nil config
func TestNewHTTPClientWithNilConfig(t *testing.T) {
	mockFactory := &mockDialerFactory{}
	factory, _ := NewSecureHTTPClientFactory(mockFactory)

	client, err := factory.NewHTTPClientWithConfig(nil)
	if err == nil {
		t.Error("Expected error when creating HTTP client with nil config, got nil")
	}
	if client != nil {
		t.Errorf("Expected nil client when creating with nil config, got %v", client)
	}
}

// Test NewHTTPClientWithConfig when dialer creation fails
func TestNewHTTPClientWithDialerCreationFailure(t *testing.T) {
	expectedError := errors.New("dialer creation failed")
	mockFactory := &mockDialerFactory{
		newTCPDialerFunc: func(config *DialerConfig) (SecureDialer, error) {
			return nil, expectedError
		},
	}
	factory, _ := NewSecureHTTPClientFactory(mockFactory)

	config := &HTTPClientConfig{
		Timeout: 10 * time.Second,
	}

	client, err := factory.NewHTTPClientWithConfig(config)
	if err == nil {
		t.Error("Expected error when dialer creation fails, got nil")
	}
	if client != nil {
		t.Errorf("Expected nil client when dialer creation fails, got %v", client)
	}
	if err != nil && !errors.Is(err, expectedError) {
		t.Errorf("Expected underlying error to be %v, got %v", expectedError, err)
	}
}

// Test Close releases resources properly
func TestSecureHTTPClientFactoryClose(t *testing.T) {
	closed := false
	mockFactory := &mockDialerFactory{
		closeFunc: func() error {
			closed = true
			return nil
		},
	}
	factory, _ := NewSecureHTTPClientFactory(mockFactory)

	err := factory.Close()
	if err != nil {
		t.Errorf("Unexpected error when closing factory: %v", err)
	}
	if !closed {
		t.Error("Expected dialer factory to be closed")
	}
}

// Test Close handles errors properly
func TestSecureHTTPClientFactoryCloseError(t *testing.T) {
	expectedError := errors.New("close failed")
	mockFactory := &mockDialerFactory{
		closeFunc: func() error {
			return expectedError
		},
	}
	factory, _ := NewSecureHTTPClientFactory(mockFactory)

	err := factory.Close()
	if err == nil {
		t.Error("Expected error when close fails, got nil")
	}
	if err != nil && !errors.Is(err, expectedError) {
		t.Errorf("Expected underlying error to be %v, got %v", expectedError, err)
	}
}

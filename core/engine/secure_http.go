package engine

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/gocircum/gocircum/pkg/securedns"
)

// SecureHTTPClientFactory creates HTTP clients that use secure DNS resolution.
type SecureHTTPClientFactory struct {
	resolver securedns.Resolver
	factory  securedns.SecureDialerFactory
}

// NewSecureHTTPClientFactory creates a new SecureHTTPClientFactory.
func NewSecureHTTPClientFactory(resolver securedns.Resolver) (*SecureHTTPClientFactory, error) {
	factory, err := securedns.NewSecureDialerFactory(resolver)
	if err != nil {
		return nil, err
	}

	return &SecureHTTPClientFactory{
		resolver: resolver,
		factory:  factory,
	}, nil
}

// NewHTTPClient creates a new HTTP client that uses secure DNS resolution.
func (f *SecureHTTPClientFactory) NewHTTPClient(timeout time.Duration) (*http.Client, error) {
	transportConfig := securedns.DefaultTransportConfig()

	// Create a secure transport
	transport, err := securedns.CreateSecureTransport(f.factory, transportConfig)
	if err != nil {
		return nil, err
	}

	// Create an HTTP client with the secure transport
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return client, nil
}

// NewHTTPClientWithTLS creates a new HTTP client with custom TLS configuration.
func (f *SecureHTTPClientFactory) NewHTTPClientWithTLS(timeout time.Duration, tlsConfig *tls.Config) (*http.Client, error) {
	transportConfig := securedns.DefaultTransportConfig()
	transportConfig.TLSConfig = tlsConfig

	// Create a secure transport
	transport, err := securedns.CreateSecureTransport(f.factory, transportConfig)
	if err != nil {
		return nil, err
	}

	// Create an HTTP client with the secure transport
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
	}

	return client, nil
}

// Close releases any resources used by the factory.
func (f *SecureHTTPClientFactory) Close() error {
	if f.factory != nil {
		return f.factory.Close()
	}
	return nil
}

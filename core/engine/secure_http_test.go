package engine

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/gocircum/gocircum/pkg/securedns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSecureHTTPClientFactory(t *testing.T) {
	// Create a mock resolver
	bootstrapConfig := &securedns.BootstrapConfig{
		BootstrapIPs: map[string][]net.IP{
			"dns.google": {net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		},
		TrustedProviders: []string{"dns.google"},
		RefreshInterval:  86400,
	}

	options := &securedns.Options{
		CacheSize:  1000,
		CacheTTL:   1800,
		Timeout:    5,
		RetryCount: 3,
	}

	resolver, err := securedns.NewDoHResolver(bootstrapConfig, options)
	require.NoError(t, err)
	defer func() {
		if err := resolver.Close(); err != nil {
			t.Logf("Error closing resolver: %v", err)
		}
	}()

	// Create the factory
	factory, err := NewSecureHTTPClientFactory(resolver)
	require.NoError(t, err)
	defer func() {
		if err := factory.Close(); err != nil {
			t.Logf("Error closing factory: %v", err)
		}
	}()

	// Verify the factory was created correctly
	assert.NotNil(t, factory)
	assert.NotNil(t, factory.resolver)
	assert.NotNil(t, factory.factory)
}

func TestSecureHTTPClientFactory_NewHTTPClient(t *testing.T) {
	// Create a mock resolver
	bootstrapConfig := &securedns.BootstrapConfig{
		BootstrapIPs: map[string][]net.IP{
			"dns.google": {net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		},
		TrustedProviders: []string{"dns.google"},
		RefreshInterval:  86400,
	}

	options := &securedns.Options{
		CacheSize:  1000,
		CacheTTL:   1800,
		Timeout:    5,
		RetryCount: 3,
	}

	resolver, err := securedns.NewDoHResolver(bootstrapConfig, options)
	require.NoError(t, err)
	defer func() {
		if err := resolver.Close(); err != nil {
			t.Logf("Error closing resolver: %v", err)
		}
	}()

	// Create the factory
	factory, err := NewSecureHTTPClientFactory(resolver)
	require.NoError(t, err)
	defer func() {
		if err := factory.Close(); err != nil {
			t.Logf("Error closing factory: %v", err)
		}
	}()

	// Create a client
	client, err := factory.NewHTTPClient(10 * time.Second)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify client properties
	assert.Equal(t, 10*time.Second, client.Timeout)
	assert.NotNil(t, client.Transport)

	// Verify it's a secure transport
	transport, ok := client.Transport.(*http.Transport)
	assert.True(t, ok)
	assert.NotNil(t, transport.DialContext)
}

func TestSecureHTTPClientFactory_NewHTTPClientWithTLS(t *testing.T) {
	// Create a mock resolver
	bootstrapConfig := &securedns.BootstrapConfig{
		BootstrapIPs: map[string][]net.IP{
			"dns.google": {net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
		},
		TrustedProviders: []string{"dns.google"},
		RefreshInterval:  86400,
	}

	options := &securedns.Options{
		CacheSize:  1000,
		CacheTTL:   1800,
		Timeout:    5,
		RetryCount: 3,
	}

	resolver, err := securedns.NewDoHResolver(bootstrapConfig, options)
	require.NoError(t, err)
	defer func() {
		if err := resolver.Close(); err != nil {
			t.Logf("Error closing resolver: %v", err)
		}
	}()

	// Create the factory
	factory, err := NewSecureHTTPClientFactory(resolver)
	require.NoError(t, err)
	defer func() {
		if err := factory.Close(); err != nil {
			t.Logf("Error closing factory: %v", err)
		}
	}()

	// Create a custom TLS config
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Create a client with the custom TLS config
	client, err := factory.NewHTTPClientWithTLS(15*time.Second, tlsConfig)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Verify client properties
	assert.Equal(t, 15*time.Second, client.Timeout)
	assert.NotNil(t, client.Transport)

	// Verify it's a secure transport
	transport, ok := client.Transport.(*http.Transport)
	assert.True(t, ok)
	assert.NotNil(t, transport.DialContext)
	assert.NotNil(t, transport.TLSClientConfig)

	// Use the actual TLS version constant value for comparison
	assert.Equal(t, uint16(tls.VersionTLS12), transport.TLSClientConfig.MinVersion)
}

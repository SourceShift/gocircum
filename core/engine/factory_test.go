package engine

import (
	"context"
	"testing"

	"github.com/gocircum/gocircum/core/config"
	"github.com/stretchr/testify/assert"
)

func TestBuildQUICUTLSConfig(t *testing.T) {
	t.Run("DefaultIsSecure", func(t *testing.T) {
		cfg := &config.TLS{
			MinVersion: "1.2",
			MaxVersion: "1.3",
		}
		utlsConfig, err := buildQUICUTLSConfig(cfg, nil)
		assert.NoError(t, err)
		assert.False(t, utlsConfig.InsecureSkipVerify, "InsecureSkipVerify should be false by default")
	})
}

func TestDefaultDialerFactoryShouldRejectHostnameResolution(t *testing.T) {
	factory := NewDefaultDialerFactory(nil)
	dialer, err := factory.NewDialer(&config.Transport{Protocol: "tcp"}, nil)
	assert.NoError(t, err)

	// Attempting to dial a hostname should fail with a security error
	conn, err := dialer(context.Background(), "tcp", "example.com:80")
	assert.Error(t, err)
	assert.Nil(t, conn)

	// Cast to SecureError and check the error details
	secErr, ok := err.(*SecureError)
	assert.True(t, ok)
	assert.Equal(t, "DNS_LEAK_PROTECTION", secErr.Code)
	assert.Equal(t, "security_violation", secErr.Type)
	assert.Equal(t, "dns_resolution", secErr.Context)
}

func TestDefaultDialerFactoryShouldAllowIPAddresses(t *testing.T) {
	factory := NewDefaultDialerFactory(nil)
	dialer, err := factory.NewDialer(&config.Transport{Protocol: "tcp"}, nil)
	assert.NoError(t, err)

	// Using an IP address should not trigger the security error
	// This test will fail if the IP doesn't respond, so use a well-known IP (localhost)
	// In a real test, you would mock the underlying dialer
	conn, err := dialer(context.Background(), "tcp", "127.0.0.1:80")

	// The connection attempt might fail because nothing is listening,
	// but it shouldn't be a security error
	if err != nil {
		_, ok := err.(*SecureError)
		assert.False(t, ok, "Using an IP address should not trigger a security error")
	} else if conn != nil {
		if closeErr := conn.Close(); closeErr != nil {
			t.Logf("Warning: failed to close connection: %v", closeErr)
		}
	}
}

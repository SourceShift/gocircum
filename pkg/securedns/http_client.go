// Package securedns provides a DNS resolution system that prevents DNS leaks
// by ensuring all DNS lookups are performed through secure channels (DoH).
package securedns

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"
)

// HTTPClientConfig contains configuration options for secure HTTP clients.
type HTTPClientConfig struct {
	// Timeout is the maximum amount of time for the entire request, including
	// connection time, redirects, and reading the response body.
	Timeout time.Duration

	// TLSHandshakeTimeout is the maximum amount of time waiting for a TLS handshake.
	TLSHandshakeTimeout time.Duration

	// DisableKeepAlives disables HTTP keep-alives if set to true.
	DisableKeepAlives bool

	// MaxIdleConns controls the maximum number of idle (keep-alive) connections.
	MaxIdleConns int

	// MaxIdleConnsPerHost controls the maximum idle connections to keep per-host.
	MaxIdleConnsPerHost int

	// IdleConnTimeout is the maximum amount of time an idle connection will remain idle before closing.
	IdleConnTimeout time.Duration

	// TLSConfig provides the TLS configuration for secure connections.
	// If nil, the default TLS configuration is used.
	TLSConfig *tls.Config
}

// SecureHTTPClientFactory creates HTTP clients that use secure DNS resolution
// to prevent DNS leaks in all HTTP requests.
type SecureHTTPClientFactory struct {
	dialerFactory SecureDialerFactory
}

// NewSecureHTTPClientFactory creates a new factory for secure HTTP clients.
func NewSecureHTTPClientFactory(dialerFactory SecureDialerFactory) (*SecureHTTPClientFactory, error) {
	if dialerFactory == nil {
		return nil, fmt.Errorf("dialer factory cannot be nil")
	}

	return &SecureHTTPClientFactory{
		dialerFactory: dialerFactory,
	}, nil
}

// NewHTTPClient creates a new HTTP client that uses secure DNS resolution.
func (f *SecureHTTPClientFactory) NewHTTPClient(timeout time.Duration) (*http.Client, error) {
	return f.NewHTTPClientWithConfig(&HTTPClientConfig{
		Timeout:             timeout,
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	})
}

// NewHTTPClientWithConfig creates a new HTTP client with the specified configuration.
func (f *SecureHTTPClientFactory) NewHTTPClientWithConfig(config *HTTPClientConfig) (*http.Client, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}

	// Create a secure dialer for TCP connections
	secureDialer, err := f.dialerFactory.NewTCPDialer(&DialerConfig{
		Timeout:   config.Timeout,
		KeepAlive: config.IdleConnTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create secure dialer: %w", err)
	}

	// Create a transport that uses our secure dialer
	transport := &http.Transport{
		DialContext: secureDialer.DialContext,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Use our secure dialer to establish the connection
			conn, err := secureDialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}

			// Get the host from the address
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				_ = conn.Close()
				return nil, err
			}

			// Create TLS config with ServerName set to the host
			tlsConfig := &tls.Config{
				ServerName:         host,
				InsecureSkipVerify: false, // Never skip verification
			}

			if config.TLSConfig != nil {
				// Copy selected fields from the provided TLS config
				if config.TLSConfig.MinVersion > 0 {
					tlsConfig.MinVersion = config.TLSConfig.MinVersion
				}
				if config.TLSConfig.MaxVersion > 0 {
					tlsConfig.MaxVersion = config.TLSConfig.MaxVersion
				}
				if len(config.TLSConfig.CipherSuites) > 0 {
					tlsConfig.CipherSuites = config.TLSConfig.CipherSuites
				}
				if config.TLSConfig.RootCAs != nil {
					tlsConfig.RootCAs = config.TLSConfig.RootCAs
				}
				if config.TLSConfig.NextProtos != nil {
					tlsConfig.NextProtos = config.TLSConfig.NextProtos
				}
			}

			// Wrap the connection with TLS
			tlsConn := tls.Client(conn, tlsConfig)
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				_ = tlsConn.Close()
				return nil, err
			}

			return tlsConn, nil
		},
		TLSHandshakeTimeout:   config.TLSHandshakeTimeout,
		DisableKeepAlives:     config.DisableKeepAlives,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true,
	}

	// Create the HTTP client with our secure transport
	client := &http.Client{
		Transport: transport,
		Timeout:   config.Timeout,
	}

	return client, nil
}

// Close releases any resources used by the factory.
func (f *SecureHTTPClientFactory) Close() error {
	return f.dialerFactory.Close()
}

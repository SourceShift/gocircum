package securedns

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// TransportConfig contains configuration options for the secure HTTP transport.
type TransportConfig struct {
	// DialerFactory is the factory for creating secure dialers.
	DialerFactory SecureDialerFactory

	// TLSConfig is the TLS configuration for the transport.
	TLSConfig *tls.Config

	// MaxIdleConns controls the maximum number of idle (keep-alive) connections.
	MaxIdleConns int

	// MaxIdleConnsPerHost controls the maximum idle (keep-alive) connections to keep per-host.
	MaxIdleConnsPerHost int

	// MaxConnsPerHost limits the total number of connections per host.
	MaxConnsPerHost int

	// IdleConnTimeout is the maximum amount of time an idle connection will remain idle before closing.
	IdleConnTimeout time.Duration

	// ResponseHeaderTimeout is the amount of time to wait for a server's response headers.
	ResponseHeaderTimeout time.Duration

	// ExpectContinueTimeout is the amount of time to wait for a server's first response headers
	// after fully writing the request headers if the request has an
	// "Expect: 100-continue" header.
	ExpectContinueTimeout time.Duration

	// DisableKeepAlives, if true, disables HTTP keep-alives and will only use
	// the connection to the server for a single HTTP request.
	DisableKeepAlives bool

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header.
	DisableCompression bool

	// ForceAttemptHTTP2 controls whether HTTP/2 is enabled when a non-zero
	// Dial, DialTLS, or DialContext func or TLSClientConfig is provided.
	// By default, use of a custom dial function or TLS config disables HTTP/2.
	// To use a custom dial function or TLS config and still attempt HTTP/2
	// upgrades, set this to true.
	ForceAttemptHTTP2 bool
}

// DefaultTransportConfig returns a default configuration for the secure HTTP transport.
func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
		DisableCompression:    false,
		ForceAttemptHTTP2:     true,
	}
}

// CreateSecureTransport creates a new HTTP transport that uses the secure dialer.
func CreateSecureTransport(factory SecureDialerFactory, config *TransportConfig) (*http.Transport, error) {
	if factory == nil {
		return nil, ErrNilFactory
	}

	if config == nil {
		config = DefaultTransportConfig()
	}

	config.DialerFactory = factory

	dialer, err := factory.NewTCPDialer(&DialerConfig{
		Timeout: 30 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	// Create a custom dialer function that uses our secure dialer
	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer.DialContext(ctx, network, addr)
	}

	// Create the transport with our custom dialer
	transport := &http.Transport{
		DialContext:           dialContext,
		MaxIdleConns:          config.MaxIdleConns,
		MaxIdleConnsPerHost:   config.MaxIdleConnsPerHost,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		IdleConnTimeout:       config.IdleConnTimeout,
		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		ExpectContinueTimeout: config.ExpectContinueTimeout,
		DisableKeepAlives:     config.DisableKeepAlives,
		DisableCompression:    config.DisableCompression,
		ForceAttemptHTTP2:     config.ForceAttemptHTTP2,
	}

	// Set TLS config if provided
	if config.TLSConfig != nil {
		transport.TLSClientConfig = config.TLSConfig
	}

	return transport, nil
}

// CreateSecureHTTPClient creates a new HTTP client that uses the secure transport.
func CreateSecureHTTPClient(factory SecureDialerFactory, transportConfig *TransportConfig) (*http.Client, error) {
	transport, err := CreateSecureTransport(factory, transportConfig)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: transport,
		Timeout:   60 * time.Second,
	}, nil
}

// ErrNilFactory is returned when a nil factory is provided.
var ErrNilFactory = NewError("nil dialer factory")

// Error is an error type for the securedns package.
type Error string

// NewError creates a new Error.
func NewError(text string) Error {
	return Error(text)
}

// Error implements the error interface.
func (e Error) Error() string {
	return string(e)
}

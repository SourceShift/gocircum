package engine

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/core/transport"
	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/gocircum/gocircum/pkg/securedns"
)

// SecureDialerFactory is a dialer factory that uses a secure DNS resolver.
type SecureDialerFactory struct {
	GetRootCAs func() *x509.CertPool
	resolver   securedns.Resolver
	factory    securedns.SecureDialerFactory
}

// NewSecureDialerFactory creates a new SecureDialerFactory.
func NewSecureDialerFactory(getRootCAs func() *x509.CertPool) (DialerFactory, error) {
	// Create bootstrap configuration for the secure resolver
	bootstrapConfig := &securedns.BootstrapConfig{
		BootstrapIPs: map[string][]net.IP{
			"dns.google":         {net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")},
			"cloudflare-dns.com": {net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1")},
			"dns.quad9.net":      {net.ParseIP("9.9.9.9"), net.ParseIP("149.112.112.112")},
		},
		TrustedProviders: []string{"dns.google", "cloudflare-dns.com", "dns.quad9.net"},
		RefreshInterval:  86400, // 24 hours in seconds
	}

	// Create options for the secure resolver
	options := &securedns.Options{
		CacheSize:                1000,
		CacheTTL:                 1800, // 30 minutes in seconds
		Timeout:                  5,    // 5 seconds
		RetryCount:               3,
		VerifyBootstrapIntegrity: true,
		BlockFallback:            false,
		UserAgent:                "GoCyrcum SecureDNS Client",
	}

	// Create the secure resolver
	resolver, err := securedns.NewDoHResolver(bootstrapConfig, options)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure resolver: %w", err)
	}

	// Create the secure dialer factory
	factory, err := securedns.NewSecureDialerFactory(resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure dialer factory: %w", err)
	}

	return &SecureDialerFactory{
		GetRootCAs: getRootCAs,
		resolver:   resolver,
		factory:    factory,
	}, nil
}

// NewDialer creates a new network dialer based on the transport configuration.
// It returns a function that can be used to establish a connection.
func (f *SecureDialerFactory) NewDialer(transportCfg *config.Transport, tlsCfg *config.TLS) (Dialer, error) {
	var baseDialer transport.Transport
	var err error

	// Create a secure dialer with appropriate timeout
	dialer := &securedns.DialerConfig{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	secureDialer, err := f.factory.NewDialer(dialer)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure dialer: %w", err)
	}

	switch transportCfg.Protocol {
	case "tcp":
		baseDialer, err = transport.NewTCPTransport(&transport.TCPConfig{})
		if err != nil {
			return nil, fmt.Errorf("failed to create TCP transport: %w", err)
		}
	case "quic":
		utlsConfig, errBuild := buildQUICUTLSConfig(tlsCfg, nil)
		if errBuild != nil {
			return nil, fmt.Errorf("failed to build uTLS config for QUIC: %w", errBuild)
		}
		baseDialer, err = transport.NewQUICTransport(&transport.QUICConfig{
			TLSConfig: utlsConfig,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create QUIC transport: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", transportCfg.Protocol)
	}

	dialerFunc := func(ctx context.Context, network, address string) (net.Conn, error) {
		host, portStr, err := net.SplitHostPort(address)
		if err != nil {
			return nil, fmt.Errorf("invalid address format: %w", err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}

		// Check if host is already an IP
		ip := net.ParseIP(host)
		if ip != nil {
			// If it's already an IP, use the base dialer directly
			conn, err := baseDialer.DialContext(ctx, network, ip, port)
			if err != nil {
				return nil, err
			}

			if transportCfg.Fragmentation != nil {
				return &fragmentingConn{
					Conn: conn,
					cfg:  transportCfg.Fragmentation,
				}, nil
			}

			return conn, nil
		}

		// If it's a hostname, use our secure dialer
		return secureDialer.DialContext(ctx, network, address)
	}

	if tlsCfg == nil {
		return dialerFunc, nil
	}

	if tlsCfg.Library == "" {
		return nil, fmt.Errorf("security policy violation: TLS configuration is present but the 'library' field is empty. Must be 'utls'")
	}

	var rootCAs *x509.CertPool
	if f.GetRootCAs != nil {
		rootCAs = f.GetRootCAs()
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		rawConn, err := dialerFunc(ctx, network, address)
		if err != nil {
			return nil, err
		}

		sni, err := validateAndExtractSNI(address, tlsCfg.ServerName)
		if err != nil {
			_ = rawConn.Close()
			logging.GetLogger().Error("SNI validation failed",
				"error", err.Error(),
				"address_sanitized", sanitizeAddress(address),
				"timestamp", time.Now().Unix())
			return nil, &ConnectionError{
				Code: "TLS_CONFIG_ERROR",
				Type: "validation_failed",
			}
		}
		return NewUTLSClient(rawConn, tlsCfg, sni, rootCAs)
	}, nil
}

// Close releases any resources used by the factory.
func (f *SecureDialerFactory) Close() error {
	if f.factory != nil {
		return f.factory.Close()
	}
	return nil
}

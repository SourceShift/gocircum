package engine

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/constants"
	"gocircum/pkg/logging"
	"net"

	utls "github.com/refraction-networking/utls"
)

// NewTLSClient wraps an existing network connection with a TLS layer,
// based on the provided TLS configuration. An optional sni can be provided
// to override the server name for the TLS handshake.
func NewTLSClient(conn net.Conn, cfg *config.TLS, serverName string, rootCAs *x509.CertPool) (net.Conn, error) {
	switch cfg.Library {
	case "go-stdlib", "stdlib":
		return newStandardTLSClient(conn, serverName, cfg, rootCAs)
	case "utls":
		return newUTLSClient(conn, serverName, cfg, rootCAs)
	case "uquic":
		// For QUIC, the TLS config is part of the transport.
		// This case is handled by the transport layer itself.
		// We return the raw connection, assuming TLS is managed by the QUIC transport.
		return conn, nil
	default:
		return nil, fmt.Errorf("unsupported TLS library: %s", cfg.Library)
	}
}

func newStandardTLSClient(conn net.Conn, serverName string, cfg *config.TLS, rootCAs *x509.CertPool) (net.Conn, error) {
	tlsConfig, err := buildStandardTLSConfig(serverName, cfg, rootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to build standard TLS config: %w", err)
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("standard TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

func newUTLSClient(conn net.Conn, serverName string, cfg *config.TLS, rootCAs *x509.CertPool) (net.Conn, error) {
	utlsConfig, err := buildUTLSConfig(serverName, cfg, rootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to build uTLS config: %w", err)
	}

	helloID, ok := constants.UTLSHelloIDMap[cfg.ClientHelloID]
	if !ok {
		return nil, fmt.Errorf("unknown uTLS ClientHelloID: %s", cfg.ClientHelloID)
	}

	uconn := utls.UClient(conn, utlsConfig, helloID)
	if err := uconn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}
	return uconn, nil
}

func buildStandardTLSConfig(serverName string, cfg *config.TLS, rootCAs *x509.CertPool) (*tls.Config, error) {
	if cfg.SkipVerify != nil && *cfg.SkipVerify {
		logging.GetLogger().Error("SECURITY WARNING: 'skip_verify: true' is configured, but this option is deprecated and IGNORED. TLS certificate validation is enforced.",
			"risk", "Man-in-the-Middle (MITM) attacks",
			"advice", "Remove 'skip_verify: true' from your configuration. This option is for testing only.",
		)
	}

	minVersion, ok := constants.TLSVersionMap[cfg.MinVersion]
	if !ok {
		return nil, fmt.Errorf("unknown min TLS version: %s", cfg.MinVersion)
	}
	maxVersion, ok := constants.TLSVersionMap[cfg.MaxVersion]
	if !ok {
		return nil, fmt.Errorf("unknown max TLS version: %s", cfg.MaxVersion)
	}

	return &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
	}, nil
}

func buildUTLSConfig(serverName string, cfg *config.TLS, rootCAs *x509.CertPool) (*utls.Config, error) {
	if cfg.SkipVerify != nil && *cfg.SkipVerify {
		logging.GetLogger().Error("SECURITY WARNING: 'skip_verify: true' is configured, but this option is deprecated and IGNORED. TLS certificate validation is enforced.",
			"risk", "Man-in-the-Middle (MITM) attacks",
			"advice", "Remove 'skip_verify: true' from your configuration. This option is for testing only.",
		)
	}

	minVersion, ok := constants.TLSVersionMap[cfg.MinVersion]
	if !ok {
		return nil, fmt.Errorf("unknown min TLS version: %s", cfg.MinVersion)
	}
	maxVersion, ok := constants.TLSVersionMap[cfg.MaxVersion]
	if !ok {
		return nil, fmt.Errorf("unknown max TLS version: %s", cfg.MaxVersion)
	}

	return &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
	}, nil
}

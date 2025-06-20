package engine

import (
	"crypto/x509"
	"fmt"
	"net"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/core/constants"
	"github.com/gocircum/gocircum/pkg/logging"
	utls "github.com/refraction-networking/utls"
)

// NewTLSClient wraps an existing network connection with a TLS layer,
// based on the provided TLS configuration. An optional sni can be provided
// to override the server name for the TLS handshake.
func NewTLSClient(conn net.Conn, cfg *config.TLS, serverName string, rootCAs *x509.CertPool) (net.Conn, error) {
	// For censorship circumvention, uTLS is strongly recommended for client-side connections.
	// Standard library TLS ClientHellos are often easily fingerprinted.
	// We'll enforce uTLS or uquic unless it's a very specific server-side use case not covered by this client logic.
	switch cfg.Library {
	case "utls":
		return newUTLSClient(conn, serverName, cfg, rootCAs)
	case "go-stdlib", "stdlib":
		// DISALLOWED: The standard library's TLS ClientHello is easily fingerprinted by censors.
		// We must not permit its use for client-side connections in a circumvention tool.
		return nil, fmt.Errorf("security policy violation: 'go-stdlib' is not a permitted TLS library for client connections due to fingerprinting risk. Use 'utls' instead")
	case "uquic":
		// For QUIC, the TLS config is part of the transport.
		// This case is handled by the transport layer itself.
		// We return the raw connection, assuming TLS is managed by the QUIC transport.
		return conn, nil
	default:
		// Default to uTLS if not specified or unknown.
		logging.GetLogger().Warn("Unknown or unspecified TLS library '%s'. Defaulting to 'utls' with 'HelloChrome_Auto'.",
			"provided_library", cfg.Library,
		)
		// Set a default for uTLS if it's not configured, but make it explicit.
		// This might require modifying the config passed in or having a more robust default logic.
		// For now, we'll return an error to force explicit configuration or better defaults.
		return nil, fmt.Errorf("unsupported or unspecified TLS library: %s. Must be 'utls' or 'uquic' for client. 'go-stdlib' is deprecated for circumvention", cfg.Library)
	}
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

func buildUTLSConfig(serverName string, cfg *config.TLS, rootCAs *x509.CertPool) (*utls.Config, error) {
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

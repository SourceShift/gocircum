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
	// For censorship circumvention, uTLS is strongly recommended for client-side connections.
	// Standard library TLS ClientHellos are often easily fingerprinted.
	// We'll enforce uTLS or uquic unless it's a very specific server-side use case not covered by this client logic.
	switch cfg.Library {
	case "utls":
		return newUTLSClient(conn, serverName, cfg, rootCAs)
	case "go-stdlib", "stdlib":
		logging.GetLogger().Warn("SECURITY WARNING: 'go-stdlib' TLS library selected. This library's TLS ClientHello fingerprint is easily detectable by DPI systems. Consider using 'utls' with a randomized ClientHelloID for better circumvention.",
			"fingerprint_id", cfg.ClientHelloID, // Provide context
			"advice", "Change 'tls.library' to 'utls' and specify a 'client_hello_id' like 'HelloRandomized'.",
		)
		// Fallback to standard TLS client, but it's not recommended for censorship circumvention.
		return newStandardTLSClient(conn, serverName, cfg, rootCAs)
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
		return nil, fmt.Errorf("unsupported or unspecified TLS library: %s. Must be 'utls' or 'uquic' for client. 'go-stdlib' is deprecated for circumvention.", cfg.Library)
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
	// For uTLS, we log a warning but always enforce verification.
	if cfg.SkipVerify != nil && *cfg.SkipVerify {
		logging.GetLogger().Warn("SECURITY WARNING: 'skip_verify: true' is configured, but this option is deprecated and IGNORED. TLS certificate validation is enforced.",
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
	// For uTLS, we log a warning but always enforce verification.
	if cfg.SkipVerify != nil && *cfg.SkipVerify {
		logging.GetLogger().Warn("SECURITY WARNING: 'skip_verify: true' is configured, but this option is deprecated and IGNORED. TLS certificate validation is enforced.",
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

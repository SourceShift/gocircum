package engine

import (
	"crypto/tls"
	"fmt"
	"gocircum/core/config"
	"net"

	utls "github.com/refraction-networking/utls"
)

// NewTLSClient wraps an existing network connection with a TLS layer,
// based on the provided TLS configuration.
func NewTLSClient(conn net.Conn, cfg *config.TLS) (net.Conn, error) {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		host = conn.RemoteAddr().String()
	}

	switch cfg.Library {
	case "stdlib":
		return newStandardTLSClient(conn, host, cfg)
	case "utls":
		return newUTLSClient(conn, host, cfg)
	default:
		return nil, fmt.Errorf("unsupported TLS library: %s", cfg.Library)
	}
}

func newStandardTLSClient(conn net.Conn, host string, cfg *config.TLS) (net.Conn, error) {
	tlsConfig, err := buildStandardTLSConfig(host, cfg)
	if err != nil {
		return nil, err
	}

	tlsConn := tls.Client(conn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("standard TLS handshake failed: %w", err)
	}
	return tlsConn, nil
}

func newUTLSClient(conn net.Conn, host string, cfg *config.TLS) (net.Conn, error) {
	utlsConfig, err := buildUTLSConfig(host, cfg)
	if err != nil {
		return nil, err
	}

	helloID, ok := UTLSHelloIDMap[cfg.ClientHelloID]
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

func buildStandardTLSConfig(host string, cfg *config.TLS) (*tls.Config, error) {
	minVersion, ok := TLSVersionMap[cfg.MinVersion]
	if !ok {
		return nil, fmt.Errorf("unknown min TLS version: %s", cfg.MinVersion)
	}
	maxVersion, ok := TLSVersionMap[cfg.MaxVersion]
	if !ok {
		return nil, fmt.Errorf("unknown max TLS version: %s", cfg.MaxVersion)
	}

	return &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // TODO: Make this configurable
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
	}, nil
}

func buildUTLSConfig(host string, cfg *config.TLS) (*utls.Config, error) {
	minVersion, ok := TLSVersionMap[cfg.MinVersion]
	if !ok {
		return nil, fmt.Errorf("unknown min TLS version: %s", cfg.MinVersion)
	}
	maxVersion, ok := TLSVersionMap[cfg.MaxVersion]
	if !ok {
		return nil, fmt.Errorf("unknown max TLS version: %s", cfg.MaxVersion)
	}

	return &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // TODO: Make this configurable
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
	}, nil
}

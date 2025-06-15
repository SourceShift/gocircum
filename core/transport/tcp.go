package transport

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// TCPConfig contains configuration options for the TCP transport.
type TCPConfig struct {
	Config
	DialTimeout time.Duration
	KeepAlive   time.Duration
	TLSConfig   *tls.Config
}

// TCPTransport implements the Transport interface for TCP connections.
type TCPTransport struct {
	dialer    *net.Dialer
	tlsConfig *tls.Config
}

// NewTCPTransport creates a new TCPTransport with the given configuration.
func NewTCPTransport(cfg *TCPConfig) (*TCPTransport, error) {
	t := &TCPTransport{
		dialer: &net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: cfg.KeepAlive,
		},
		tlsConfig: cfg.TLSConfig,
	}
	return t, nil
}

// DialContext connects to the given address using TCP. If TLS config is provided,
// it performs a TLS handshake.
func (t *TCPTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err // TODO: Wrap error
	}

	if t.tlsConfig != nil {
		// We need to ensure the ServerName is set for SNI,
		// which is crucial for TLS and circumvention.
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			// If SplitHostPort fails, it might be because the port is missing.
			// In that case, the address itself is likely the host.
			host = address
		}

		clientTLSConfig := t.tlsConfig.Clone()
		if clientTLSConfig.ServerName == "" {
			clientTLSConfig.ServerName = host
		}

		tlsConn := tls.Client(conn, clientTLSConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, err // TODO: Wrap error
		}
		return tlsConn, nil
	}

	return conn, nil
}

// Listen creates a listener on the specified network address. If a TLS config
// is provided, it returns a TLS listener.
func (t *TCPTransport) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, network, address)
	if err != nil {
		return nil, err // TODO: wrap error
	}

	if t.tlsConfig != nil {
		return tls.NewListener(ln, t.tlsConfig), nil
	}

	return ln, nil
}

// Close is a no-op for TCPTransport as it doesn't hold persistent resources itself.
// The connections it creates are managed individually.
func (t *TCPTransport) Close() error {
	return nil
}

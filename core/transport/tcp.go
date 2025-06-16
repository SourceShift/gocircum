package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"gocircum/pkg/logging"
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
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}

	if t.tlsConfig != nil {
		// We need to ensure the ServerName is set for SNI,
		// which is crucial for TLS and circumvention.
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			// If SplitHostPort fails, it might be because the port is missing.
			// In that case, the address itself is likely the host.
			logging.GetLogger().Warn("could not split host/port, falling back to using address as host", "address", address, "error", err)
			host = address
		}

		clientTLSConfig := t.tlsConfig.Clone()
		if clientTLSConfig.ServerName == "" {
			clientTLSConfig.ServerName = host
		}

		tlsConn := tls.Client(conn, clientTLSConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake failed: %w", err)
		}
		return tlsConn, nil
	}

	return conn, nil
}

// Listen creates a listener on the specified network address. If a TLS config
// is provided, it returns a TLS listener.
func (t *TCPTransport) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("tcp listen failed: %w", err)
	}

	// Wrap the listener to respect context cancellation for Accept() calls.
	wrapper := newTCPListenerWrapper(ctx, ln)

	if t.tlsConfig != nil {
		return tls.NewListener(wrapper, t.tlsConfig), nil
	}

	return wrapper, nil
}

// tcpListenerWrapper wraps a net.Listener to make its Accept method cancellable.
type tcpListenerWrapper struct {
	net.Listener
	ctx context.Context
}

// newTCPListenerWrapper creates a new wrapper and starts a goroutine to close
// the listener when the context is done.
func newTCPListenerWrapper(ctx context.Context, l net.Listener) *tcpListenerWrapper {
	lw := &tcpListenerWrapper{
		Listener: l,
		ctx:      ctx,
	}

	go func() {
		<-ctx.Done()
		// Closing the listener will cause the blocking Accept() call to return an error.
		_ = lw.Listener.Close()
	}()

	return lw
}

// Accept waits for and returns the next connection to the listener.
// It will unblock and return an error if the listener's context is cancelled.
func (l *tcpListenerWrapper) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		// If the context was cancelled, this error is expected.
		// We check the context's error to provide a more specific reason.
		select {
		case <-l.ctx.Done():
			return nil, l.ctx.Err()
		default:
			// The error was not due to context cancellation.
			return nil, fmt.Errorf("accept failed: %w", err)
		}
	}
	return conn, nil
}

// Close is a no-op for TCPTransport as it doesn't hold persistent resources itself.
// The connections it creates are managed individually.
func (t *TCPTransport) Close() error {
	return nil
}

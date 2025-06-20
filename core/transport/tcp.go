package transport

import (
	"context"
	"fmt"
	"net"
	"time"
)

// TCPConfig contains configuration options for the TCP transport.
type TCPConfig struct {
	Config
	DialTimeout time.Duration
	KeepAlive   time.Duration
}

// TCPTransport is a transport that uses TCP.
type TCPTransport struct {
	dialer *net.Dialer
}

// NewTCPTransport creates a new TCPTransport with the given configuration.
func NewTCPTransport(cfg *TCPConfig) (*TCPTransport, error) {
	t := &TCPTransport{
		dialer: &net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: cfg.KeepAlive,
		},
	}
	return t, nil
}

// DialContext connects to the given address using raw TCP. It no longer handles TLS.
// TLS negotiation is now handled exclusively by higher-level components (e.g., engine.NewTLSClient)
// to enforce the uTLS security policy.
func (t *TCPTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
	return conn, nil
}

// Listen creates a listener on the specified network address. It no longer handles TLS.
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
		_ = lw.Close()
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

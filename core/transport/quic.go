package transport

import (
	"context"
	"errors"
	"net"
	"time"

	quic "github.com/refraction-networking/uquic"
	utls "github.com/refraction-networking/utls"
)

// QUICConfig contains configuration options for the QUIC transport.
type QUICConfig struct {
	TLSConfig  *utls.Config
	QUICConfig *quic.Config
}

// QUICTransport implements the Transport interface for QUIC connections.
type QUICTransport struct {
	tlsConfig  *utls.Config
	quicConfig *quic.Config
}

// NewQUICTransport creates a new QUICTransport with the given configuration.
func NewQUICTransport(cfg *QUICConfig) (*QUICTransport, error) {
	if cfg.TLSConfig == nil {
		return nil, errors.New("TLSConfig is required for QUIC transport")
	}
	return &QUICTransport{
		tlsConfig:  cfg.TLSConfig,
		quicConfig: cfg.QUICConfig,
	}, nil
}

// DialContext connects to the given address using QUIC.
func (t *QUICTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := quic.DialAddr(ctx, address, t.tlsConfig, t.quicConfig)
	if err != nil {
		return nil, err
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}

	return &quicConn{Stream: stream, conn: conn}, nil
}

// Listen starts a QUIC listener on the given address.
func (t *QUICTransport) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	l, err := quic.ListenAddr(address, t.tlsConfig, t.quicConfig)
	if err != nil {
		return nil, err
	}
	return &quicListenerWrapper{listener: l, ctx: ctx}, nil
}

// Close is a no-op for the QUIC transport itself.
func (t *QUICTransport) Close() error {
	return nil
}

// quicListenerWrapper wraps a *quic.Listener to implement the net.Listener interface.
type quicListenerWrapper struct {
	listener *quic.Listener // This is a pointer to the concrete quic.Listener struct
	ctx      context.Context
}

// Accept waits for and returns the next connection to the listener.
func (l *quicListenerWrapper) Accept() (net.Conn, error) {
	conn, err := l.listener.Accept(l.ctx)
	if err != nil {
		return nil, err
	}

	stream, err := conn.AcceptStream(l.ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, err
	}
	return &quicConn{Stream: stream, conn: conn}, nil
}

// Close closes the listener.
func (l *quicListenerWrapper) Close() error {
	return l.listener.Close()
}

// Addr returns the listener's network address.
func (l *quicListenerWrapper) Addr() net.Addr {
	return l.listener.Addr()
}

// quicConn wraps a quic.Stream and quic.Connection to implement the net.Conn interface.
type quicConn struct {
	quic.Stream
	conn quic.Connection
}

// Close closes the stream and the underlying QUIC connection.
func (c *quicConn) Close() error {
	err := c.Stream.Close()
	err2 := c.conn.CloseWithError(0, "closing")
	if err != nil {
		return err
	}
	return err2
}

func (c *quicConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *quicConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *quicConn) SetDeadline(t time.Time) error {
	_ = c.Stream.SetReadDeadline(t)
	return c.Stream.SetWriteDeadline(t)
}

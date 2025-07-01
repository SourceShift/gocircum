package transport

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
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
	tlsConfig          *utls.Config
	quicConfig         *quic.Config
	obfuscationTarget  ObfuscationTarget
	obfuscationEnabled bool
	decoyTrafficRate   time.Duration
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
func (t *QUICTransport) DialContext(ctx context.Context, network string, ip net.IP, port int) (net.Conn, error) {
	if ip == nil {
		return nil, errors.New("ip address cannot be nil")
	}
	address := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
	conn, err := quic.DialAddr(ctx, address, t.tlsConfig, t.quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic dial failed: %w", err)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		_ = conn.CloseWithError(0, "")
		return nil, fmt.Errorf("quic open stream failed: %w", err)
	}

	return &quicConn{Stream: stream, conn: conn}, nil
}

// Listen starts a QUIC listener on the given address.
func (t *QUICTransport) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	l, err := quic.ListenAddr(address, t.tlsConfig, t.quicConfig)
	if err != nil {
		return nil, fmt.Errorf("quic listen failed: %w", err)
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
		// Check if the error is due to context cancellation.
		select {
		case <-l.ctx.Done():
			return nil, l.ctx.Err()
		default:
			return nil, fmt.Errorf("quic accept failed: %w", err)
		}
	}

	stream, err := conn.AcceptStream(l.ctx)
	if err != nil {
		// If accepting the stream fails, we should also check for context cancellation.
		_ = conn.CloseWithError(0, "")
		select {
		case <-l.ctx.Done():
			return nil, l.ctx.Err()
		default:
			return nil, fmt.Errorf("quic accept stream failed: %w", err)
		}
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
	if err != nil {
		// Try to close the connection anyway.
		_ = c.conn.CloseWithError(0, "closing")
		return fmt.Errorf("quic stream close failed: %w", err)
	}
	err2 := c.conn.CloseWithError(0, "closing")
	if err2 != nil {
		return fmt.Errorf("quic conn close failed: %w", err2)
	}
	return nil
}

func (c *quicConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *quicConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
}

func (c *quicConn) SetDeadline(t time.Time) error {
	_ = c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

// GetFingerprint returns the network-observable characteristics of this transport
func (t *QUICTransport) GetFingerprint() TransportFingerprint {
	return TransportFingerprint{
		Protocol:         "quic",
		PacketSizes:      []int{1200, 1280, 1472}, // Typical QUIC packet sizes
		TimingPattern:    []time.Duration{20 * time.Millisecond, 50 * time.Millisecond},
		TLSSignature:     "quic-standard",
		ObfuscationLevel: t.getObfuscationLevel(),
	}
}

// GenerateDecoyTraffic creates realistic background traffic to mask real connections
func (t *QUICTransport) GenerateDecoyTraffic(ctx context.Context, targetIP net.IP, targetPort int) error {
	if !t.obfuscationEnabled || t.decoyTrafficRate == 0 {
		return nil // Decoy traffic disabled
	}

	if targetIP == nil {
		return errors.New("targetIP cannot be nil for decoy traffic")
	}
	targetAddr := net.JoinHostPort(targetIP.String(), fmt.Sprintf("%d", targetPort))

	go func() {
		ticker := time.NewTicker(t.decoyTrafficRate)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Generate a small decoy connection
				if err := t.generateSingleDecoyConnection(ctx, "udp", targetAddr); err != nil {
					// Log error but don't stop decoy traffic generation
					continue
				}
			}
		}
	}()

	return nil
}

// SupportsObfuscation indicates if the transport can masquerade as other protocols
func (t *QUICTransport) SupportsObfuscation() bool {
	return t.obfuscationEnabled
}

// SetObfuscationTarget configures the transport to mimic a specific protocol
func (t *QUICTransport) SetObfuscationTarget(target ObfuscationTarget) error {
	t.obfuscationTarget = target
	t.obfuscationEnabled = true
	return nil
}

// Helper methods for obfuscation

func (t *QUICTransport) getObfuscationLevel() ObfuscationLevel {
	if !t.obfuscationEnabled {
		return ObfuscationNone
	}

	switch t.obfuscationTarget {
	case ObfuscateAsHTTP, ObfuscateAsSSH:
		return ObfuscationBasic
	case ObfuscateAsBitTorrent, ObfuscateAsVideoStream:
		return ObfuscationAdvanced
	case ObfuscateAsVoIP, ObfuscateAsWebRTC:
		return ObfuscationMaximal
	default:
		return ObfuscationBasic
	}
}

func (t *QUICTransport) generateSingleDecoyConnection(ctx context.Context, network, targetAddr string) error {
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ipStr, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return fmt.Errorf("invalid target address for decoy connection: %w", err)
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return fmt.Errorf("invalid IP in target address for decoy connection: %s", ipStr)
	}
	port, err := net.LookupPort("udp", portStr)
	if err != nil {
		port, err = strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("invalid port in target address for decoy connection: %w", err)
		}
	}

	conn, err := t.DialContext(dialCtx, network, ip, port)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()

	// Send some realistic-looking data based on obfuscation target
	data := t.generateDecoyData()
	if len(data) > 0 {
		_, _ = conn.Write(data)

		// Wait for a realistic amount of time
		delay := t.generateRealisticDelay()
		time.Sleep(delay)
	}

	return nil
}

func (t *QUICTransport) generateDecoyData() []byte {
	switch t.obfuscationTarget {
	case ObfuscateAsWebRTC:
		// WebRTC-like STUN binding request
		return []byte{0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42}
	case ObfuscateAsVoIP:
		// RTP-like header
		return []byte{0x80, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}
	default:
		// Generate random data
		size, _ := rand.Int(rand.Reader, big.NewInt(512))
		data := make([]byte, 32+size.Int64())
		_, _ = rand.Read(data)
		return data
	}
}

func (t *QUICTransport) generateRealisticDelay() time.Duration {
	// Generate random delay between 10ms and 500ms
	delay, _ := rand.Int(rand.Reader, big.NewInt(490))
	return time.Duration(10+delay.Int64()) * time.Millisecond
}

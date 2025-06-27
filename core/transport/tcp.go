package transport

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"time"
)

// TCPConfig contains configuration options for the TCP transport.
type TCPConfig struct {
	Config
	DialTimeout time.Duration
	KeepAlive   time.Duration
}

// TCPTransport is a transport that uses TCP with obfuscation capabilities.
type TCPTransport struct {
	dialer            *net.Dialer
	obfuscationTarget ObfuscationTarget
	obfuscationEnabled bool
	decoyTrafficRate  time.Duration
}

// NewTCPTransport creates a new TCPTransport with the given configuration.
func NewTCPTransport(cfg *TCPConfig) (*TCPTransport, error) {
	t := &TCPTransport{
		dialer: &net.Dialer{
			Timeout:   cfg.DialTimeout,
			KeepAlive: cfg.KeepAlive,
		},
		obfuscationEnabled: cfg.ObfuscationEnabled,
		obfuscationTarget:  cfg.ObfuscationTarget,
		decoyTrafficRate:   cfg.DecoyTrafficRate,
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

// GetFingerprint returns the network-observable characteristics of this transport
func (t *TCPTransport) GetFingerprint() TransportFingerprint {
	return TransportFingerprint{
		Protocol:         "tcp",
		PacketSizes:      []int{1460, 1448, 536}, // Typical TCP packet sizes
		TimingPattern:    []time.Duration{50 * time.Millisecond, 100 * time.Millisecond},
		TLSSignature:     "tcp-standard",
		ObfuscationLevel: t.getObfuscationLevel(),
	}
}

// GenerateDecoyTraffic creates realistic background traffic to mask real connections
func (t *TCPTransport) GenerateDecoyTraffic(ctx context.Context, targetAddr string) error {
	if !t.obfuscationEnabled || t.decoyTrafficRate == 0 {
		return nil // Decoy traffic disabled
	}

	go func() {
		ticker := time.NewTicker(t.decoyTrafficRate)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Generate a small decoy connection
				if err := t.generateSingleDecoyConnection(targetAddr); err != nil {
					// Log error but don't stop decoy traffic generation
					continue
				}
			}
		}
	}()

	return nil
}

// SupportsObfuscation indicates if the transport can masquerade as other protocols
func (t *TCPTransport) SupportsObfuscation() bool {
	return t.obfuscationEnabled
}

// SetObfuscationTarget configures the transport to mimic a specific protocol
func (t *TCPTransport) SetObfuscationTarget(target ObfuscationTarget) error {
	t.obfuscationTarget = target
	t.obfuscationEnabled = true
	return nil
}

// Helper methods for obfuscation

func (t *TCPTransport) getObfuscationLevel() ObfuscationLevel {
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

func (t *TCPTransport) generateSingleDecoyConnection(targetAddr string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := t.dialer.DialContext(ctx, "tcp", targetAddr)
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

func (t *TCPTransport) generateDecoyData() []byte {
	switch t.obfuscationTarget {
	case ObfuscateAsHTTP:
		return []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n")
	case ObfuscateAsSSH:
		return []byte("SSH-2.0-OpenSSH_8.0\r\n")
	case ObfuscateAsBitTorrent:
		// BitTorrent handshake-like data
		data := make([]byte, 68)
		data[0] = 19 // Protocol name length
		copy(data[1:20], "BitTorrent protocol")
		return data
	default:
		// Generate random data
		size, _ := rand.Int(rand.Reader, big.NewInt(512))
		data := make([]byte, 32+size.Int64())
		_, _ = rand.Read(data)
		return data
	}
}

func (t *TCPTransport) generateRealisticDelay() time.Duration {
	// Generate random delay between 10ms and 500ms
	delay, _ := rand.Int(rand.Reader, big.NewInt(490))
	return time.Duration(10+delay.Int64()) * time.Millisecond
}

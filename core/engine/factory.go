package engine

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/core/constants"
	"github.com/gocircum/gocircum/core/transport"
	"github.com/gocircum/gocircum/pkg/logging"

	utls "github.com/refraction-networking/utls"
)

var PopularUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
}

//go:generate mockgen -package=mocks -destination=../../mocks/mock_dialer_factory.go github.com/gocircum/gocircum/core/engine DialerFactory

// Dialer is a function that can establish a network connection.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// DialerFactory creates a Dialer based on transport and TLS configurations.
type DialerFactory interface {
	NewDialer(transportCfg *config.Transport, tlsCfg *config.TLS) (Dialer, error)
}

// DefaultDialerFactory is the default implementation of DialerFactory.
type DefaultDialerFactory struct {
	GetRootCAs func() *x509.CertPool
}

// NewDefaultDialerFactory creates a new DefaultDialerFactory.
func NewDefaultDialerFactory(getRootCAs func() *x509.CertPool) DialerFactory {
	return &DefaultDialerFactory{GetRootCAs: getRootCAs}
}

// NewDialer creates a new network dialer based on the transport configuration.
// It returns a function that can be used to establish a connection.
func (f *DefaultDialerFactory) NewDialer(transportCfg *config.Transport, tlsCfg *config.TLS) (Dialer, error) {
	var baseDialer transport.Transport

	switch transportCfg.Protocol {
	case "tcp":
		var err error
		// ARCHITECTURAL ENFORCEMENT: The factory's responsibility for TCP is to
		// provide a raw, transport-level connection. TLS wrapping is explicitly
		// handled by higher-level components (e.g., domain fronting dialer).
		// We enforce this by asserting that no TLS config is passed for TCP.
		if tlsCfg != nil {
			return nil, fmt.Errorf("architectural violation: NewDialer received a non-nil TLS config for a TCP transport; TLS must be handled by the caller")
		}

		// The TCP transport no longer handles TLS. We just create a basic TCP config.
		baseDialer, err = transport.NewTCPTransport(&transport.TCPConfig{})
		if err != nil {
			return nil, fmt.Errorf("failed to create TCP transport: %w", err)
		}
	case "quic":
		utlsConfig, err := buildQUICUTLSConfig(tlsCfg, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to build uTLS config for QUIC: %w", err)
		}
		baseDialer, err = transport.NewQUICTransport(&transport.QUICConfig{
			TLSConfig: utlsConfig,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create QUIC transport: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", transportCfg.Protocol)
	}

	// Wrap the dialer in fragmentation middleware if configured.
	if transportCfg.Fragmentation != nil {
		middleware := newFragmenter(transportCfg.Fragmentation)
		baseDialer = middleware(baseDialer)
	}

	rawDialer := baseDialer.DialContext

	// Hardened: Enforce TLS if the configuration block is present.
	if tlsCfg == nil {
		// No TLS configuration was provided at all, return raw dialer.
		// Note: Higher-level logic should prevent this for circumvention strategies.
		return rawDialer, nil
	}

	// If tlsCfg is not nil, we MUST establish a TLS connection.
	// We rely on validation to have already checked the library.
	if tlsCfg.Library == "" {
		return nil, fmt.Errorf("security policy violation: TLS configuration is present but the 'library' field is empty. Must be 'utls'")
	}

	var rootCAs *x509.CertPool
	if f.GetRootCAs != nil {
		rootCAs = f.GetRootCAs()
	}

	return func(ctx context.Context, network, address string) (net.Conn, error) {
		rawConn, err := rawDialer(ctx, network, address)
		if err != nil {
			return nil, err
		}

		// The SNI should be the host part of the address, unless overridden in the config.
		sni := tlsCfg.ServerName
		if sni == "" {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				sni = address // Fallback to address if SplitHostPort fails
			} else {
				sni = host
			}
		}

		// NewUTLSClient will handle the library check and handshake.
		return NewUTLSClient(rawConn, tlsCfg, sni, rootCAs)
	}, nil
}

func buildQUICUTLSConfig(cfg *config.TLS, rootCAs *x509.CertPool) (*utls.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	minVersion, ok := constants.TLSVersionMap[cfg.MinVersion]
	if !ok && cfg.MinVersion != "" {
		return nil, fmt.Errorf("unknown min TLS version: %s", cfg.MinVersion)
	}
	maxVersion, ok := constants.TLSVersionMap[cfg.MaxVersion]
	if !ok && cfg.MaxVersion != "" {
		return nil, fmt.Errorf("unknown max TLS version: %s", cfg.MaxVersion)
	}
	if cfg.MinVersion == "" {
		minVersion = utls.VersionTLS12
	}
	if cfg.MaxVersion == "" {
		maxVersion = utls.VersionTLS13
	}

	// The `InsecureSkipVerify` field is explicitly and immutably set to false.
	// It does not read from any configuration struct, enforcing security at compile time.
	return &utls.Config{
		InsecureSkipVerify: false, // This is a security policy, not a configuration option.
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		RootCAs:            rootCAs,
	}, nil
}

func BuildUTLSConfig(cfg *config.TLS, rootCAs *x509.CertPool) (*utls.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	minVersion, ok := constants.TLSVersionMap[cfg.MinVersion]
	if !ok && cfg.MinVersion != "" {
		return nil, fmt.Errorf("unknown min TLS version: %s", cfg.MinVersion)
	}
	maxVersion, ok := constants.TLSVersionMap[cfg.MaxVersion]
	if !ok && cfg.MaxVersion != "" {
		return nil, fmt.Errorf("unknown max TLS version: %s", cfg.MaxVersion)
	}
	if cfg.MinVersion == "" {
		minVersion = utls.VersionTLS12
	}
	if cfg.MaxVersion == "" {
		maxVersion = utls.VersionTLS13
	}

	// The `InsecureSkipVerify` field is explicitly and immutably set to false.
	// It does not read from any configuration struct, enforcing security at compile time.
	return &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: false, // This is a security policy, not a configuration option.
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
		RootCAs:            rootCAs,
	}, nil
}

var clientHelloIDMap = map[string]utls.ClientHelloID{
	"HelloChrome_Auto":       utls.HelloChrome_Auto,
	"HelloFirefox_Auto":      utls.HelloFirefox_Auto,
	"HelloIOS_Auto":          utls.HelloIOS_Auto,
	"HelloAndroid_11_OkHttp": utls.HelloAndroid_11_OkHttp,
	"Randomized":             utls.HelloRandomized,
	"RandomizedNoALPN":       utls.HelloRandomizedNoALPN,
}

func NewUTLSClient(rawConn net.Conn, tlsCfg *config.TLS, sni string, customRootCAs *x509.CertPool) (net.Conn, error) {
	utlsConfig, err := BuildUTLSConfig(tlsCfg, customRootCAs)
	if err != nil {
		return nil, fmt.Errorf("failed to build uTLS config: %w", err)
	}
	utlsConfig.ServerName = sni

	helloID := utls.HelloRandomized
	if tlsCfg.ClientHelloID != "" {
		id, ok := clientHelloIDMap[tlsCfg.ClientHelloID]
		if !ok {
			return nil, fmt.Errorf("unknown or unsupported client hello ID: %s", tlsCfg.ClientHelloID)
		}
		helloID = id
	}

	uconn := utls.UClient(rawConn, utlsConfig, helloID)
	if err := uconn.Handshake(); err != nil {
		return nil, fmt.Errorf("uTLS handshake failed: %w", err)
	}
	return uconn, nil
}

// newFragmenter creates a middleware that fragments the initial data chunks (i.e. ClientHello)
func newFragmenter(cfg *config.Fragmentation) transport.Middleware {
	return func(base transport.Transport) transport.Transport {
		return &fragmentingTransport{
			Transport: base,
			cfg:       cfg,
		}
	}
}

type fragmentingTransport struct {
	transport.Transport
	cfg *config.Fragmentation
}

func (t *fragmentingTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := t.Transport.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial for fragmentation failed: %w", err)
	}
	return &fragmentingConn{
		Conn: conn,
		cfg:  t.cfg,
	}, nil
}

type fragmentingConn struct {
	net.Conn
	cfg         *config.Fragmentation
	wrotePacket bool
}

// Write fragments the first Write call, which should contain the ClientHello.
func (c *fragmentingConn) Write(b []byte) (n int, err error) {
	// Only fragment the first Write call.
	if c.wrotePacket {
		return c.Conn.Write(b)
	}
	c.wrotePacket = true

	switch c.cfg.Algorithm {
	case "static":
		return c.writeStatic(b)
	case "even":
		return c.writeEven(b)
	default:
		// Default to static distribution if the type is unknown or not specified.
		return c.writeStatic(b)
	}
}

// writeStatic fragments the ClientHello into chunks of predetermined sizes.
func (c *fragmentingConn) writeStatic(b []byte) (n int, err error) {
	totalSent := 0
	remaining := len(b)
	packetSizes := c.cfg.PacketSizes
	delayRange := c.cfg.DelayMs

	for i, sizeRange := range packetSizes {
		if remaining == 0 {
			break
		}

		minChunk := sizeRange[0]
		maxChunk := sizeRange[1]

		var chunkSize int
		// HARDENED: Fail the connection if we cannot generate a secure random number.
		chunkSize, err = CryptoRandInt(minChunk, maxChunk)
		if err != nil {
			c.logError(err, "fatal: cannot generate secure random number for chunk size")
			return totalSent, fmt.Errorf("CSPRNG failure for fragmentation: %w", err)
		}

		if chunkSize > remaining {
			chunkSize = remaining
		}

		sent, writeErr := c.Conn.Write(b[totalSent : totalSent+chunkSize])
		if writeErr != nil {
			return totalSent, writeErr
		}
		totalSent += sent
		remaining -= sent

		isLastChunk := (i == len(packetSizes)-1) || (remaining == 0)
		if !isLastChunk {
			var delayMs int
			// HARDENED: Fail the connection if we cannot generate a secure random number.
			delayMs, err = CryptoRandInt(delayRange[0], delayRange[1])
			if err != nil {
				c.logError(err, "fatal: cannot generate secure random number for delay")
				return totalSent, fmt.Errorf("CSPRNG failure for fragmentation delay: %w", err)
			}
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}

	// If there's any data left over, send it in one last chunk.
	if remaining > 0 {
		sent, writeErr := c.Conn.Write(b[totalSent:])
		if writeErr != nil {
			return totalSent, writeErr
		}
		totalSent += sent
	}

	return totalSent, nil
}

// writeEven fragments the ClientHello into chunks of random sizes within a configured range.
// The number of chunks is not fixed; instead, we send random-sized chunks until the
// entire payload is sent. This is more robust against fingerprinting than a fixed number of chunks.
func (c *fragmentingConn) writeEven(b []byte) (n int, err error) {
	totalSent := 0
	remaining := len(b)

	if len(c.cfg.PacketSizes) == 0 {
		return 0, fmt.Errorf("fragmentation config for 'even' algorithm is missing packet_sizes")
	}
	// For 'even' distribution, we use the first entry in PacketSizes for min/max chunk size.
	minSize := c.cfg.PacketSizes[0][0]
	maxSize := c.cfg.PacketSizes[0][1]

	// And DelayMs for min/max delay.
	minDelay := c.cfg.DelayMs[0]
	maxDelay := c.cfg.DelayMs[1]

	for remaining > 0 {
		var chunkSize int
		// HARDENED: Fail the connection if we cannot generate a secure random number.
		// Continuing with a predictable default would create a fingerprint.
		chunkSize, err := CryptoRandInt(minSize, maxSize)
		if err != nil {
			c.logError(err, "fatal: cannot generate secure random number for chunk size")
			// Return an error to abort the Write and the connection attempt.
			return totalSent, fmt.Errorf("CSPRNG failure for fragmentation: %w", err)
		}

		if chunkSize > remaining {
			chunkSize = remaining
		}
		// Ensure we always make progress and don't get stuck in a loop.
		if chunkSize <= 0 && remaining > 0 {
			chunkSize = remaining
		}

		sent, err := c.Conn.Write(b[totalSent : totalSent+chunkSize])
		if err != nil {
			return totalSent, err
		}

		totalSent += sent
		remaining -= sent

		if remaining > 0 {
			var delayMs int
			// HARDENED: Fail the connection if we cannot generate a secure random number.
			delayMs, err := CryptoRandInt(minDelay, maxDelay)
			if err != nil {
				c.logError(err, "fatal: cannot generate secure random number for delay")
				// Return an error to abort the Write and the connection attempt.
				return totalSent, fmt.Errorf("CSPRNG failure for fragmentation delay: %w", err)
			}

			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}
	return totalSent, nil
}

func (c *fragmentingConn) logError(err error, msg string) {
	logger := logging.GetLogger()
	// A basic logger that prints to stderr.
	// In a real application, this would use the configured logger.
	// For now, we avoid adding a logger field to fragmentingConn to minimize changes.
	logger.Error(msg, "error", err)
}

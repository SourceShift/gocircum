package engine

import (
	"context"
	"crypto/x509"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/constants"
	"gocircum/core/transport"
	"gocircum/pkg/logging"
	"net"
	"time"

	"crypto/tls"

	utls "github.com/refraction-networking/utls"
)

var PopularUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
}

//go:generate mockgen -package=mocks -destination=../../mocks/mock_dialer_factory.go gocircum/core/engine DialerFactory

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

// NewDialer creates a new network dialer based on the transport configuration.
// It returns a function that can be used to establish a connection.
func (f *DefaultDialerFactory) NewDialer(transportCfg *config.Transport, tlsCfg *config.TLS) (Dialer, error) {
	var baseDialer transport.Transport

	switch transportCfg.Protocol {
	case "tcp":
		stdLibTlsConfig, err := buildStdLibTLSConfig(tlsCfg, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to build stdlib tls config: %w", err)
		}

		baseDialer, err = transport.NewTCPTransport(&transport.TCPConfig{
			TLSConfig: stdLibTlsConfig,
		})
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

	// If TLS is configured, wrap the raw dialer in a TLS handshake.
	if tlsCfg != nil && tlsCfg.Library != "" {
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

			return NewUTLSClient(rawConn, tlsCfg, sni, rootCAs)
		}, nil
	}

	return rawDialer, nil
}

func buildStdLibTLSConfig(cfg *config.TLS, rootCAs *x509.CertPool) (*tls.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	return &tls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: false,
		RootCAs:            rootCAs,
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

	return &utls.Config{
		InsecureSkipVerify: false,
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

	return &utls.Config{
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: false,
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
	case "even":
		return c.writeEven(b)
	case "static", "": // Default to static
		return c.writeStatic(b)
	default:
		c.logError(fmt.Errorf("unknown fragmentation algorithm: %s", c.cfg.Algorithm), "unknown fragmentation algorithm, falling back to static")
		return c.writeStatic(b)
	}
}

// writeStatic fragments the data based on the static ranges defined in the config.
func (c *fragmentingConn) writeStatic(b []byte) (n int, err error) {
	totalSent := 0
	for i, sizeRange := range c.cfg.PacketSizes {
		if len(b) == 0 {
			break
		}

		minSize, maxSize := sizeRange[0], sizeRange[1]
		chunkSize := minSize
		if maxSize > minSize {
			secureRand, err := CryptoRandInt(minSize, maxSize)
			if err != nil {
				c.logError(err, "failed to generate secure random number for chunk size")
				return totalSent, err
			}
			chunkSize = secureRand
		}

		if chunkSize > len(b) {
			chunkSize = len(b)
		}

		sent, err := c.Conn.Write(b[:chunkSize])
		if err != nil {
			return totalSent + sent, fmt.Errorf("fragmented write failed: %w", err)
		}
		totalSent += sent
		b = b[sent:]

		// Apply delay if there's more data to send
		if len(b) > 0 && i < len(c.cfg.PacketSizes)-1 {
			minDelay, maxDelay := c.cfg.DelayMs[0], c.cfg.DelayMs[1]
			delayMs := minDelay
			if maxDelay > minDelay {
				secureRand, err := CryptoRandInt(minDelay, maxDelay)
				if err != nil {
					c.logError(err, "failed to generate secure random number for delay")
					return totalSent, err
				}
				delayMs = secureRand
			}
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}

	// Send any remaining data in one go
	if len(b) > 0 {
		sent, err := c.Conn.Write(b)
		if err != nil {
			return totalSent + sent, fmt.Errorf("final fragmented write failed: %w", err)
		}
		totalSent += sent
	}

	return totalSent, nil
}

// writeEven splits the data into a specified number of even-sized chunks.
// The number of chunks is taken from the first PacketSizes entry.
func (c *fragmentingConn) writeEven(b []byte) (n int, err error) {
	if len(c.cfg.PacketSizes) == 0 || c.cfg.PacketSizes[0][0] <= 0 {
		c.logError(fmt.Errorf("invalid number of chunks for 'even' algorithm"), "invalid config for 'even' fragmentation")
		return c.Conn.Write(b) // Fallback to no fragmentation
	}
	numChunks := c.cfg.PacketSizes[0][0]
	if numChunks == 1 {
		return c.Conn.Write(b)
	}

	chunkSize := len(b) / numChunks
	if chunkSize == 0 {
		chunkSize = 1 // Avoid infinite loop for small payloads
	}

	totalSent := 0
	for len(b) > 0 {
		currentChunkSize := chunkSize
		if currentChunkSize > len(b) {
			currentChunkSize = len(b)
		}

		// To make it slightly less predictable, we can add a small random variation to chunk size
		if len(b) > currentChunkSize { // Don't randomize the last chunk
			variation, _ := CryptoRandInt(0, chunkSize/5)
			currentChunkSize += (variation - chunkSize/10)
			if currentChunkSize <= 0 {
				currentChunkSize = 1
			}
		}

		sent, err := c.Conn.Write(b[:currentChunkSize])
		if err != nil {
			return totalSent + sent, fmt.Errorf("fragmented write failed: %w", err)
		}
		totalSent += sent
		b = b[sent:]

		if len(b) > 0 {
			minDelay, maxDelay := c.cfg.DelayMs[0], c.cfg.DelayMs[1]
			delayMs := minDelay
			if maxDelay > minDelay {
				secureRand, err := CryptoRandInt(minDelay, maxDelay)
				if err != nil {
					c.logError(err, "failed to generate secure random number for delay")
					return totalSent, err
				}
				delayMs = secureRand
			}
			time.Sleep(time.Duration(delayMs) * time.Millisecond)
		}
	}

	return totalSent, nil
}

func (c *fragmentingConn) logError(err error, msg string) {
	// A basic logger that prints to stderr.
	// In a real application, this would use the configured logger.
	// For now, we avoid adding a logger field to fragmentingConn to minimize changes.
	logging.GetLogger().Error(msg, "error", err)
}

package engine

import (
	"context"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/constants"
	"gocircum/core/transport"
	"gocircum/pkg/logging"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

//go:generate mockgen -package=mocks -destination=../../mocks/mock_dialer_factory.go gocircum/core/engine DialerFactory

// Dialer is a function that can establish a network connection.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// DialerFactory creates a Dialer based on transport and TLS configurations.
type DialerFactory interface {
	NewDialer(transportCfg *config.Transport, tlsCfg *config.TLS) (Dialer, error)
}

// DefaultDialerFactory is the default implementation of DialerFactory.
type DefaultDialerFactory struct{}

// NewDialer creates a new network dialer based on the transport configuration.
// It returns a function that can be used to establish a connection.
func (f *DefaultDialerFactory) NewDialer(transportCfg *config.Transport, tlsCfg *config.TLS) (Dialer, error) {
	var dialer transport.Transport
	var err error

	switch transportCfg.Protocol {
	case "tcp":
		dialer, err = transport.NewTCPTransport(&transport.TCPConfig{})
		if err != nil {
			return nil, fmt.Errorf("failed to create TCP transport: %w", err)
		}
	case "quic":
		utlsConfig, err := buildQUICUTLSConfig(tlsCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to build uTLS config for QUIC: %w", err)
		}
		dialer, err = transport.NewQUICTransport(&transport.QUICConfig{
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
		dialer = middleware(dialer)
	}

	return dialer.DialContext, nil
}

func buildQUICUTLSConfig(cfg *config.TLS) (*utls.Config, error) {
	if cfg.SkipVerify != nil && *cfg.SkipVerify {
		logging.GetLogger().Error("SECURITY WARNING: 'skip_verify: true' is configured for a QUIC strategy, but this option is deprecated and IGNORED. TLS certificate validation is enforced.",
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
		InsecureSkipVerify: false,
		MinVersion:         minVersion,
		MaxVersion:         maxVersion,
	}, nil
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

	totalSent := 0
	for i, sizeRange := range c.cfg.PacketSizes {
		if len(b) == 0 {
			break
		}

		minSize, maxSize := sizeRange[0], sizeRange[1]
		chunkSize := minSize
		if maxSize > minSize {
			secureRand, err := cryptoRandInt(minSize, maxSize)
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
				secureRand, err := cryptoRandInt(minDelay, maxDelay)
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

func (c *fragmentingConn) logError(err error, msg string) {
	// A basic logger that prints to stderr.
	// In a real application, this would use the configured logger.
	// For now, we avoid adding a logger field to fragmentingConn to minimize changes.
	logging.GetLogger().Error(msg, "error", err)
}

package engine

import (
	"context"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/transport"
	"math/rand"
	"net"
	"time"
)

// NewDialer creates a new network dialer based on the transport configuration.
// It returns a function that can be used to establish a connection.
func NewDialer(cfg *config.Transport) (func(ctx context.Context, network, addr string) (net.Conn, error), error) {
	var dialer transport.Transport
	var err error

	// The TLS config is handled by the client factory, so we pass nil here.
	switch cfg.Protocol {
	case "tcp":
		dialer, err = transport.NewTCPTransport(&transport.TCPConfig{
			// TLSConfig is handled by the client factory
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create TCP transport: %w", err)
		}
	case "quic":
		// QUIC requires a TLS config, but we create a temporary one here.
		// The real TLS config will be applied by the client factory.
		// This is a limitation of the current uquic library.
		dialer, err = transport.NewQUICTransport(&transport.QUICConfig{
			// TLSConfig is handled by the client factory
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create QUIC transport: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", cfg.Protocol)
	}

	// Wrap the dialer in fragmentation middleware if configured.
	if cfg.Fragmentation != nil {
		middleware := newFragmenter(cfg.Fragmentation)
		dialer = middleware(dialer)
	}

	return dialer.DialContext, nil
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
		return nil, err
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
			chunkSize += rand.Intn(maxSize - minSize + 1)
		}
		if chunkSize > len(b) {
			chunkSize = len(b)
		}

		sent, err := c.Conn.Write(b[:chunkSize])
		if err != nil {
			return totalSent + sent, err
		}
		totalSent += sent
		b = b[sent:]

		// Apply delay if there's more data to send
		if len(b) > 0 && i < len(c.cfg.PacketSizes)-1 {
			minDelay, maxDelay := c.cfg.DelayMs[0], c.cfg.DelayMs[1]
			delay := time.Duration(minDelay) * time.Millisecond
			if maxDelay > minDelay {
				delay += time.Duration(rand.Intn(maxDelay-minDelay+1)) * time.Millisecond
			}
			time.Sleep(delay)
		}
	}

	// Send any remaining data in one go
	if len(b) > 0 {
		sent, err := c.Conn.Write(b)
		if err != nil {
			return totalSent + sent, err
		}
		totalSent += sent
	}

	return totalSent, nil
}

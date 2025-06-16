package transport

import (
	"context"
	"fmt"
	"net"
	"time"
)

// fragmentingConn is a wrapper around net.Conn that fragments Write calls.
type fragmentingConn struct {
	net.Conn
	fragmentSize  int
	fragmentDelay time.Duration
}

// Write fragments the data into smaller chunks and sends them with a delay.
func (c *fragmentingConn) Write(b []byte) (n int, err error) {
	totalSent := 0
	for len(b) > 0 {
		chunkSize := c.fragmentSize
		if chunkSize > len(b) {
			chunkSize = len(b)
		}

		sent, err := c.Conn.Write(b[:chunkSize])
		if err != nil {
			return totalSent + sent, fmt.Errorf("fragmented write failed: %w", err)
		}

		totalSent += sent
		b = b[sent:]

		if len(b) > 0 && c.fragmentDelay > 0 {
			time.Sleep(c.fragmentDelay)
		}
	}
	return totalSent, nil
}

// fragmentingTransport is a transport wrapper that creates fragmenting connections.
type fragmentingTransport struct {
	Transport
	fragmentSize  int
	fragmentDelay time.Duration
}

// DialContext wraps the established connection with fragmentation logic.
func (t *fragmentingTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := t.Transport.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("dial for fragmentation failed: %w", err)
	}
	return &fragmentingConn{
		Conn:          conn,
		fragmentSize:  t.fragmentSize,
		fragmentDelay: t.fragmentDelay,
	}, nil
}

// FragmentationMiddleware creates a middleware that fragments outgoing data.
func FragmentationMiddleware(size int, delay time.Duration) Middleware {
	return func(base Transport) Transport {
		return &fragmentingTransport{
			Transport:     base,
			fragmentSize:  size,
			fragmentDelay: delay,
		}
	}
}

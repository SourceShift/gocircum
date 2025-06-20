//go:generate mockgen -package=mocks -destination=../../mocks/mock_transport.go github.com/gocircum/gocircum/core/transport Transport

package transport

import (
	"context"
	"errors"
	"net"
	"time"
)

// Transport is the interface for network transports.
// It abstracts the underlying protocol (TCP, QUIC, etc.).
type Transport interface {
	// DialContext connects to the given address.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
	// Listen creates a listener on the specified network address.
	Listen(ctx context.Context, network, address string) (net.Listener, error)
	// Close closes the transport, releasing any resources.
	Close() error
}

// Middleware is a function that wraps a Transport to add functionality.
type Middleware func(transport Transport) Transport

// Config is a placeholder for common configuration options.
type Config struct {
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
}

// Factory is a function that creates a new Transport with the given config.
type Factory func(cfg *Config) (Transport, error)

// Custom error types for the transport layer.
var (
	ErrTimeout   = &net.DNSError{Err: "i/o timeout", IsTimeout: true}
	ErrHandshake = errors.New("handshake failed")
)

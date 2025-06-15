package transport

import (
	"context"
	"net"
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
// TODO: Expand with common options like timeouts.
type Config struct{}

// Factory is a function that creates a new Transport with the given config.
type Factory func(cfg *Config) (Transport, error)

// TODO: Define specific transport-related error types here.

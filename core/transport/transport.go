package transport

import (
	"context"
	"io"
	"net"
)

// Transport defines the interface for a generic network transport.
// It is responsible for establishing and managing the underlying connection.
type Transport interface {
	// DialContext connects to the address on the named network using
	// the provided context.
	DialContext(ctx context.Context, network, address string) (net.Conn, error)

	// Listen creates a listener on the specified network address.
	Listen(ctx context.Context, network, address string) (net.Listener, error)

	// io.Closer is responsible for closing the transport's underlying resources.
	io.Closer
}

// Config holds the common configuration options for a transport.
// Specific transport implementations may embed this and add their own options.
type Config struct {
	// TODO: Add common transport configuration fields here,
	// e.g., timeouts, buffer sizes, etc.
}

// Factory is a function that creates a new Transport with the given config.
type Factory func(cfg *Config) (Transport, error)

// Middleware is a function that wraps a Transport to add functionality.
type Middleware func(transport Transport) Transport

// TODO: Define specific transport-related error types here.

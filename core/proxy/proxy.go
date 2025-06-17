package proxy

import (
	"context"
	"fmt"
	"net"

	"gocircum/core/config"

	"github.com/armon/go-socks5"
)

// CustomDialer is a function that can establish a network connection.
// This allows the SOCKS5 server to use our custom transport stacks.
type CustomDialer func(ctx context.Context, network, address string) (net.Conn, error)

// Proxy wraps the SOCKS5 server and manages its lifecycle.
type Proxy struct {
	server   *socks5.Server
	listener net.Listener
}

// New creates and configures a new SOCKS5 proxy.
// It takes a listening address, a custom dialer function, and a slice of DoH providers.
func New(addr string, dialer CustomDialer, dohProviders []config.DoHProvider) (*Proxy, error) {
	conf := &socks5.Config{
		// The custom dialer is the key to integrating our transport logic.
		Dial:     dialer,
		Resolver: NewDoHResolver(dohProviders),
	}

	server, err := socks5.New(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to create socks5 server: %w", err)
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr, err)
	}

	return &Proxy{
		server:   server,
		listener: listener,
	}, nil
}

// Start runs the SOCKS5 proxy server.
func (p *Proxy) Start() error {
	// The Serve method is blocking, so it should be run in a goroutine
	// by the caller (e.g., the core Engine).
	return p.server.Serve(p.listener)
}

// Stop gracefully shuts down the proxy server.
func (p *Proxy) Stop() error {
	if p.listener == nil {
		return nil
	}
	return p.listener.Close()
}

// Addr returns the listening address of the proxy.
func (p *Proxy) Addr() string {
	if p.listener == nil {
		return ""
	}
	return p.listener.Addr().String()
}

// GetListener returns the underlying net.Listener. This is used for testing.
func (p *Proxy) GetListener() net.Listener {
	return p.listener
}

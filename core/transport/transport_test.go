package transport

import (
	"context"
	"errors"
	"net"
	"testing"
)

// mockTransport is a mock implementation of the Transport interface for testing.
type mockTransport struct {
	dialer   func(ctx context.Context, network, address string) (net.Conn, error)
	listener func(ctx context.Context, network, address string) (net.Listener, error)
	closer   func() error
}

func (m *mockTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if m.dialer != nil {
		return m.dialer(ctx, network, address)
	}
	return nil, errors.New("dial not implemented")
}

func (m *mockTransport) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	if m.listener != nil {
		return m.listener(ctx, network, address)
	}
	return nil, errors.New("listen not implemented")
}

func (m *mockTransport) Close() error {
	if m.closer != nil {
		return m.closer()
	}
	return nil
}

// TestFactory tests the transport factory pattern.
func TestFactory(t *testing.T) {
	var factory Factory = func(cfg *Config) (Transport, error) {
		return &mockTransport{}, nil
	}

	transport, err := factory(&Config{})
	if err != nil {
		t.Fatalf("Factory returned an unexpected error: %v", err)
	}

	if transport == nil {
		t.Fatal("Factory returned a nil transport")
	}
}

// TestMiddleware tests the middleware pattern.
func TestMiddleware(t *testing.T) {
	baseTransport := &mockTransport{
		closer: func() error {
			t.Log("Base transport closed")
			return nil
		},
	}

	var mw Middleware = func(tr Transport) Transport {
		return &mockTransport{
			closer: func() error {
				t.Log("Middleware cleaning up...")
				return tr.Close()
			},
		}
	}

	wrappedTransport := mw(baseTransport)
	if err := wrappedTransport.Close(); err != nil {
		t.Fatalf("Middleware Close returned an error: %v", err)
	}
}

// TestInterfaces tests that the defined interfaces can be used as expected.
func TestInterfaces(t *testing.T) {
	transport := &mockTransport{
		dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &net.TCPConn{}, nil
		},
	}

	conn, err := transport.DialContext(context.Background(), "tcp", "localhost:8080")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext returned a nil connection")
	}
	_ = conn.Close()

	if err := transport.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

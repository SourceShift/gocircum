package transport_test

import (
	"bytes"
	"context"
	"errors"
	"gocircum/core/transport"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
	var factory transport.Factory = func(cfg *transport.Config) (transport.Transport, error) {
		return &mockTransport{}, nil
	}

	tr, err := factory(&transport.Config{})
	if err != nil {
		t.Fatalf("Factory returned an unexpected error: %v", err)
	}

	if tr == nil {
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

	var mw transport.Middleware = func(tr transport.Transport) transport.Transport {
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
	tr := &mockTransport{
		dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			return &net.TCPConn{}, nil
		},
	}

	conn, err := tr.DialContext(context.Background(), "tcp", "localhost:8080")
	if err != nil {
		t.Fatalf("DialContext failed: %v", err)
	}
	if conn == nil {
		t.Fatal("DialContext returned a nil connection")
	}
	_ = conn.Close()

	if err := tr.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
}

func TestTCPTransport_DialContext_ErrorWrapping(t *testing.T) {
	// Use a non-routable address to force a dial error.
	nonRoutableAddress := "192.0.2.1:1234"
	tcpTransport, err := transport.NewTCPTransport(&transport.TCPConfig{
		DialTimeout: time.Millisecond * 10,
	})
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*50)
	defer cancel()

	_, err = tcpTransport.DialContext(ctx, "tcp", nonRoutableAddress)

	assert.Error(t, err)

	// Check if the underlying error is a net.OpError, which is what DialContext usually returns on timeout.
	var opErr *net.OpError
	assert.True(t, errors.As(err, &opErr), "error should be a net.OpError")
	assert.True(t, opErr.Timeout(), "OpError should be a timeout")
}

func TestTCPTransport_Listen_ErrorWrapping(t *testing.T) {
	// Use a privileged port to force a listen error.
	privilegedAddress := "127.0.0.1:80"
	tcpTransport, err := transport.NewTCPTransport(&transport.TCPConfig{})
	assert.NoError(t, err)

	_, err = tcpTransport.Listen(context.Background(), "tcp", privilegedAddress)
	assert.Error(t, err)

	// The underlying error should be a net.OpError for listen failures.
	var opErr *net.OpError
	assert.True(t, errors.As(err, &opErr), "error should be a net.OpError")
}

func TestLoggingMiddleware(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)

	// Create a mock transport
	mock := &mockTransport{
		closer: func() error {
			return nil
		},
	}

	// Create the logging middleware
	loggingMW := transport.LoggingMiddleware(logger)
	wrappedTransport := loggingMW(mock)

	// Call a method and check the log output
	_, _ = wrappedTransport.DialContext(context.Background(), "tcp", "127.0.0.1:8080")
	assert.Contains(t, buf.String(), "Dialing tcp://127.0.0.1:8080")
	buf.Reset() // Reset buffer for the next check

	_, _ = wrappedTransport.Listen(context.Background(), "tcp", "127.0.0.1:8080")
	assert.Contains(t, buf.String(), "Listening on tcp://127.0.0.1:8080")
	buf.Reset()

	_ = wrappedTransport.Close()
	assert.Contains(t, buf.String(), "Closing transport")
}

func TestChainMiddleware(t *testing.T) {
	var order []string

	// Create two simple middlewares that record their application order
	mw1 := func(base transport.Transport) transport.Transport {
		order = append(order, "mw1_applied")
		return base
	}

	mw2 := func(base transport.Transport) transport.Transport {
		order = append(order, "mw2_applied")
		return base
	}

	// Chain them
	chainedMW := transport.Chain(mw1, mw2)

	// Apply the chained middleware
	chainedMW(&mockTransport{})

	// Middlewares are applied from last to first (wrapping order)
	expectedOrder := "mw2_applied mw1_applied"
	actualOrder := strings.Join(order, " ")

	assert.Equal(t, expectedOrder, actualOrder)
}

func TestTimeoutMiddleware(t *testing.T) {
	// Create a mock transport that blocks to simulate a slow dial
	mock := &mockTransport{
		dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			select {
			case <-time.After(100 * time.Millisecond):
				return nil, errors.New("should have timed out")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}

	// Wrap it with a short timeout
	timeoutMW := transport.TimeoutMiddleware(10 * time.Millisecond)
	wrappedTransport := timeoutMW(mock)

	// This dial should fail with a context deadline exceeded error
	_, err := wrappedTransport.DialContext(context.Background(), "tcp", "localhost:1234")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestRetryMiddleware(t *testing.T) {
	attempts := 0
	maxAttempts := 3

	// Create a mock transport that fails a few times before succeeding
	mock := &mockTransport{
		dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			attempts++
			if attempts < maxAttempts {
				return nil, errors.New("connection failed")
			}
			// Use a mock connection that does nothing, since we only care about the dial success
			return &net.TCPConn{}, nil
		},
	}

	// Wrap it with the retry middleware
	retryMW := transport.RetryMiddleware(maxAttempts, 1*time.Millisecond)
	wrappedTransport := retryMW(mock)

	// This dial should succeed after several attempts
	conn, err := wrappedTransport.DialContext(context.Background(), "tcp", "localhost:1234")
	assert.NoError(t, err)
	defer func() { _ = conn.Close() }()

	assert.Equal(t, maxAttempts, attempts)
}

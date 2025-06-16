package transport_test

import (
	"bytes"
	"context"
	"errors"
	"gocircum/core/transport"
	"gocircum/mocks"
	"gocircum/testutils"
	"log"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestFactory tests the transport factory pattern.
func TestFactory(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var factory transport.Factory = func(cfg *transport.Config) (transport.Transport, error) {
		return mocks.NewMockTransport(ctrl), nil
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	baseTransport := mocks.NewMockTransport(ctrl)
	baseTransport.EXPECT().Close().Return(nil).Times(1).Do(func() {
		t.Log("Base transport closed")
	})

	var mw transport.Middleware = func(tr transport.Transport) transport.Transport {
		// In a real scenario, the middleware would wrap the transport.
		// For this test, we just ensure it calls the base transport's methods.
		return tr
	}

	wrappedTransport := mw(baseTransport)
	if err := wrappedTransport.Close(); err != nil {
		t.Fatalf("Middleware Close returned an error: %v", err)
	}
}

// TestInterfaces tests that the defined interfaces can be used as expected.
func TestInterfaces(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	tr := mocks.NewMockTransport(ctrl)
	connMock := testutils.NewMockConn(ctrl)

	tr.EXPECT().DialContext(gomock.Any(), "tcp", "localhost:8080").Return(connMock, nil)
	connMock.EXPECT().Close().Return(nil)
	tr.EXPECT().Close().Return(nil)

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
	// Find a free port and immediately close the listener to ensure the port is not in use.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedPortAddress := listener.Addr().String()
	require.NoError(t, listener.Close())

	tcpTransport, err := transport.NewTCPTransport(&transport.TCPConfig{
		DialTimeout: time.Millisecond * 100, // Increased timeout for reliability
	})
	assert.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second) // Increased context timeout
	defer cancel()

	_, err = tcpTransport.DialContext(ctx, "tcp", closedPortAddress)

	assert.Error(t, err)

	// Check if the underlying error is a net.OpError, which is what DialContext usually returns on connection refused.
	var opErr *net.OpError
	assert.True(t, errors.As(err, &opErr), "error should be a net.OpError")
	// We expect a "connect: connection refused" error, not a timeout.
	assert.Contains(t, opErr.Err.Error(), "connection refused", "expected a connection refused error")
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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	connMock := testutils.NewMockConn(ctrl)
	listenerMock := testutils.NewMockListener(ctrl)

	// Create a mock transport
	mock := mocks.NewMockTransport(ctrl)
	mock.EXPECT().DialContext(gomock.Any(), gomock.Any(), gomock.Any()).Return(connMock, nil).AnyTimes()
	mock.EXPECT().Listen(gomock.Any(), gomock.Any(), gomock.Any()).Return(listenerMock, nil).AnyTimes()
	mock.EXPECT().Close().Return(nil).AnyTimes()
	connMock.EXPECT().RemoteAddr().Return(&net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 5678}).AnyTimes()
	listenerMock.EXPECT().Addr().Return(&net.TCPAddr{IP: net.IPv4(1, 2, 3, 4), Port: 8080}).AnyTimes()

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
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
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
	chainedMW(mocks.NewMockTransport(ctrl))

	// Middlewares are applied from last to first (wrapping order)
	expectedOrder := "mw2_applied mw1_applied"
	actualOrder := strings.Join(order, " ")

	assert.Equal(t, expectedOrder, actualOrder)
}

func TestTimeoutMiddleware(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// Create a mock transport that blocks to simulate a slow dial
	mock := mocks.NewMockTransport(ctrl)
	mock.EXPECT().DialContext(gomock.Any(), gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, network, address string) (net.Conn, error) {
			// Block until the context is cancelled by the timeout middleware.
			// This is more efficient than a fixed-duration sleep.
			<-ctx.Done()
			return nil, ctx.Err()
		},
	)

	// Wrap it with a short timeout
	timeoutMW := transport.TimeoutMiddleware(10 * time.Millisecond)
	wrappedTransport := timeoutMW(mock)

	// Create a parent context with a timeout to prevent the test from hanging
	parentCtx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This dial should fail with a context deadline exceeded error
	_, err := wrappedTransport.DialContext(parentCtx, "tcp", "localhost:1234")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}

func TestRetryMiddleware(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	attempts := 0
	maxAttempts := 3

	// Create a mock transport that fails a few times before succeeding
	mock := mocks.NewMockTransport(ctrl)
	connMock := testutils.NewMockConn(ctrl)

	// Create a context with timeout to prevent the test from hanging
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	mock.EXPECT().DialContext(gomock.Any(), gomock.Any(), gomock.Any()).
		DoAndReturn(func(ctx context.Context, network, address string) (net.Conn, error) {
			attempts++
			if attempts < maxAttempts {
				return nil, errors.New("connection failed")
			}
			return connMock, nil
		}).Times(maxAttempts)

	connMock.EXPECT().Close().Return(nil).AnyTimes()

	// Wrap it with the retry middleware
	retryMW := transport.RetryMiddleware(maxAttempts, 1*time.Millisecond)
	wrappedTransport := retryMW(mock)

	// This dial should succeed after several attempts
	conn, err := wrappedTransport.DialContext(ctx, "tcp", "localhost:1234")
	if err != nil {
		t.Fatalf("Expected successful connection after retries, got error: %v", err)
	}
	if conn == nil {
		t.Fatal("Expected non-nil connection after retries")
	}
	defer func() { _ = conn.Close() }()

	assert.Equal(t, maxAttempts, attempts)
}

package transport

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

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
	loggingMW := LoggingMiddleware(logger)
	wrappedTransport := loggingMW(mock)

	// Call a method and check the log output
	wrappedTransport.DialContext(context.Background(), "tcp", "127.0.0.1:8080")
	if !strings.Contains(buf.String(), "Dialing tcp://127.0.0.1:8080") {
		t.Errorf("Expected log message for Dial, but got: %s", buf.String())
	}
	buf.Reset() // Reset buffer for the next check

	wrappedTransport.Listen(context.Background(), "tcp", "127.0.0.1:8080")
	if !strings.Contains(buf.String(), "Listening on tcp://127.0.0.1:8080") {
		t.Errorf("Expected log message for Listen, but got: %s", buf.String())
	}
	buf.Reset()

	wrappedTransport.Close()
	if !strings.Contains(buf.String(), "Closing transport") {
		t.Errorf("Expected log message for Close, but got: %s", buf.String())
	}
}

func TestChainMiddleware(t *testing.T) {
	var order []string

	// Create two simple middlewares that record their application order
	mw1 := func(base Transport) Transport {
		order = append(order, "mw1_applied")
		return base
	}

	mw2 := func(base Transport) Transport {
		order = append(order, "mw2_applied")
		return base
	}

	// Chain them
	chainedMW := Chain(mw1, mw2)

	// Apply the chained middleware
	chainedMW(&mockTransport{})

	// Middlewares are applied from last to first (wrapping order)
	expectedOrder := "mw2_applied mw1_applied"
	actualOrder := strings.Join(order, " ")

	if actualOrder != expectedOrder {
		t.Errorf("Expected middleware order '%s', but got '%s'", expectedOrder, actualOrder)
	}
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
	timeoutMW := TimeoutMiddleware(10 * time.Millisecond)
	wrappedTransport := timeoutMW(mock)

	// This dial should fail with a context deadline exceeded error
	_, err := wrappedTransport.DialContext(context.Background(), "tcp", "localhost:1234")
	if err == nil {
		t.Fatal("Expected an error, but got nil")
	}

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Expected context.DeadlineExceeded error, but got: %v", err)
	}
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
	retryMW := RetryMiddleware(maxAttempts, 1*time.Millisecond)
	wrappedTransport := retryMW(mock)

	// This dial should succeed after several attempts
	conn, err := wrappedTransport.DialContext(context.Background(), "tcp", "localhost:1234")
	if err != nil {
		t.Fatalf("Expected a successful connection, but got error: %v", err)
	}
	defer conn.Close()

	if attempts != maxAttempts {
		t.Errorf("Expected %d attempts, but got %d", maxAttempts, attempts)
	}
}

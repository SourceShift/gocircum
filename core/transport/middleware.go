package transport

import (
	"context"
	"log"
	"net"
	"time"

	"golang.org/x/time/rate"
)

// Chain creates a single Middleware from a series of middlewares.
// The middlewares are applied in the order they are passed.
func Chain(middlewares ...Middleware) Middleware {
	return func(base Transport) Transport {
		for i := len(middlewares) - 1; i >= 0; i-- {
			base = middlewares[i](base)
		}
		return base
	}
}

// loggingTransport is a transport wrapper that logs method calls.
type loggingTransport struct {
	Transport
	logger *log.Logger
}

// DialContext logs the dial call and then calls the underlying transport's DialContext.
func (t *loggingTransport) DialContext(ctx context.Context, network string, ip net.IP, port int) (net.Conn, error) {
	t.logger.Printf("Dialing %s://%s:%d", network, ip, port)
	conn, err := t.Transport.DialContext(ctx, network, ip, port)
	if err != nil {
		t.logger.Printf("Dial failed: %v", err)
	} else {
		t.logger.Printf("Dial successful to %s", conn.RemoteAddr())
	}
	return conn, err
}

// Listen logs the listen call and then calls the underlying transport's Listen.
func (t *loggingTransport) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	t.logger.Printf("Listening on %s://%s", network, address)
	listener, err := t.Transport.Listen(ctx, network, address)
	if err != nil {
		t.logger.Printf("Listen failed: %v", err)
	} else {
		t.logger.Printf("Listening on %s", listener.Addr())
	}
	return listener, err
}

// Close logs the close call and then calls the underlying transport's Close.
func (t *loggingTransport) Close() error {
	t.logger.Printf("Closing transport")
	return t.Transport.Close()
}

// LoggingMiddleware creates a middleware that logs transport operations.
func LoggingMiddleware(logger *log.Logger) Middleware {
	return func(base Transport) Transport {
		return &loggingTransport{
			Transport: base,
			logger:    logger,
		}
	}
}

// timeoutTransport is a transport wrapper that applies a timeout to operations.
type timeoutTransport struct {
	Transport
	timeout time.Duration
}

// DialContext applies a timeout to the dial operation.
func (t *timeoutTransport) DialContext(ctx context.Context, network string, ip net.IP, port int) (net.Conn, error) {
	if t.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.timeout)
		defer cancel()
	}
	return t.Transport.DialContext(ctx, network, ip, port)
}

// TimeoutMiddleware creates a middleware that applies a timeout to dial operations.
func TimeoutMiddleware(timeout time.Duration) Middleware {
	return func(base Transport) Transport {
		return &timeoutTransport{
			Transport: base,
			timeout:   timeout,
		}
	}
}

// retryTransport is a transport wrapper that retries failed dial attempts.
type retryTransport struct {
	Transport
	attempts int
	delay    time.Duration
}

// DialContext retries dialing on failure up to the configured number of attempts.
func (t *retryTransport) DialContext(ctx context.Context, network string, ip net.IP, port int) (net.Conn, error) {
	var lastErr error
	for i := 0; i < t.attempts; i++ {
		conn, err := t.Transport.DialContext(ctx, network, ip, port)
		if err == nil {
			return conn, nil
		}
		lastErr = err

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(t.delay):
			// continue to next attempt
		}
	}
	return nil, lastErr
}

// RetryMiddleware creates a middleware that retries failed dial attempts.
func RetryMiddleware(attempts int, delay time.Duration) Middleware {
	return func(base Transport) Transport {
		return &retryTransport{
			Transport: base,
			attempts:  attempts,
			delay:     delay,
		}
	}
}

// throttlingTransport is a transport wrapper that rate limits dial attempts.
type throttlingTransport struct {
	Transport
	limiter *rate.Limiter
}

// DialContext waits for a token from the rate limiter before dialing.
func (t *throttlingTransport) DialContext(ctx context.Context, network string, ip net.IP, port int) (net.Conn, error) {
	if err := t.limiter.Wait(ctx); err != nil {
		return nil, err
	}
	return t.Transport.DialContext(ctx, network, ip, port)
}

// ThrottlingMiddleware creates a middleware for rate limiting dial attempts.
func ThrottlingMiddleware(r rate.Limit, b int) Middleware {
	limiter := rate.NewLimiter(r, b)
	return func(base Transport) Transport {
		return &throttlingTransport{
			Transport: base,
			limiter:   limiter,
		}
	}
}

# Error Handling Guidelines

This document outlines the standards for error handling in the gocircum codebase, with a focus on error wrapping and inspection.

## Error Wrapping Standard

All errors returned from functions that call other fallible functions should be "wrapped" to provide context. This helps in debugging by creating a chain of errors that shows the path of failure.

We use `fmt.Errorf` with the `%w` verb to wrap errors.

**✅ Good Example:**

```go
// From: core/transport/tcp.go

func (t *TCPTransport) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := t.dialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, fmt.Errorf("tcp dial failed: %w", err)
	}
    // ...
}
```

In this example, if `t.dialer.DialContext` returns an error, it is wrapped with the message "tcp dial failed:". This provides immediate context about where the error occurred in our application logic.

**❌ Bad Example (Avoid):**

```go
// Old code to be avoided
if err != nil {
    return nil, err // This loses context
}
```

## Swallowing vs. Logging Errors

In some cases, an error can be handled gracefully, and the program can continue. However, the error should not be "swallowed" silently. If an error occurs but doesn't prevent the function from continuing, it should be logged.

**✅ Good Example:**

```go
// From: core/engine/client_factory.go

func NewTLSClient(conn net.Conn, cfg *config.TLS) (net.Conn, error) {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		log.Printf("could not split host/port for %q (falling back to using address as host): %v", conn.RemoteAddr().String(), err)
		host = conn.RemoteAddr().String()
	}
    // ...
}
```
Here, `net.SplitHostPort` might fail if the address doesn't have a port, but the code can recover by using the whole address as the host. Instead of ignoring the error, it's logged for visibility.

## Error Inspection

Wrapped errors can be inspected to check for specific underlying error types or values. This is crucial for robust error handling logic. We use `errors.As()` and `errors.Is()`.

### `errors.As()` - Checking for a Type

Use `errors.As()` to check if an error in the chain matches a specific type.

**✅ Good Example (from tests):**

```go
// From: core/transport/transport_test.go

func TestTCPTransport_DialContext_ErrorWrapping(t *testing.T) {
    // ...
	_, err = tcpTransport.DialContext(ctx, "tcp", nonRoutableAddress)

	assert.Error(t, err)

	// Check if the underlying error is a net.OpError
	var opErr *net.OpError
	assert.True(t, errors.As(err, &opErr), "error should be a net.OpError")
	assert.True(t, opErr.Timeout(), "OpError should be a timeout")
}
```

### `errors.Is()` - Checking for a Value

Use `errors.Is()` to check if an error in the chain matches a specific error value (e.g., a sentinel error like `context.DeadlineExceeded`).

**✅ Good Example (from tests):**

```go
// From: core/transport/transport_test.go

func TestTimeoutMiddleware(t *testing.T) {
    // ...
	_, err := wrappedTransport.DialContext(context.Background(), "tcp", "localhost:1234")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}
```

By adhering to these standards, we create a more robust and debuggable codebase. 
package securedns

import (
	"context"
	"net"
)

// MockResolver implements the Resolver interface for testing purposes.
type MockResolver struct {
	lookupIPFunc          func(ctx context.Context, host string) ([]net.IP, error)
	lookupIPWithCacheFunc func(ctx context.Context, host string) ([]net.IP, error)
	preloadCacheFunc      func(entries map[string][]net.IP)
	verifyNoLeaksFunc     func(ctx context.Context) error
	closeFunc             func() error
}

// LookupIP implements the Resolver interface.
func (m *MockResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	if m.lookupIPFunc != nil {
		return m.lookupIPFunc(ctx, host)
	}
	return []net.IP{net.ParseIP("127.0.0.1")}, nil
}

// LookupIPWithCache implements the Resolver interface.
func (m *MockResolver) LookupIPWithCache(ctx context.Context, host string) ([]net.IP, error) {
	if m.lookupIPWithCacheFunc != nil {
		return m.lookupIPWithCacheFunc(ctx, host)
	}
	return m.LookupIP(ctx, host)
}

// PreloadCache implements the Resolver interface.
func (m *MockResolver) PreloadCache(entries map[string][]net.IP) {
	if m.preloadCacheFunc != nil {
		m.preloadCacheFunc(entries)
	}
}

// VerifyNoLeaks implements the Resolver interface.
func (m *MockResolver) VerifyNoLeaks(ctx context.Context) error {
	if m.verifyNoLeaksFunc != nil {
		return m.verifyNoLeaksFunc(ctx)
	}
	return nil
}

// Close implements the Resolver interface.
func (m *MockResolver) Close() error {
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	return nil
}

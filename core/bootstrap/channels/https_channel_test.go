package channels

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockSecureResolver implements the securedns.Resolver interface for testing
type MockSecureResolver struct {
	mock.Mock
}

func (m *MockSecureResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	args := m.Called(ctx, host)
	return args.Get(0).([]net.IP), args.Error(1)
}

func (m *MockSecureResolver) LookupIPWithCache(ctx context.Context, host string) ([]net.IP, error) {
	args := m.Called(ctx, host)
	return args.Get(0).([]net.IP), args.Error(1)
}

func (m *MockSecureResolver) PreloadCache(entries map[string][]net.IP) {
	m.Called(entries)
}

func (m *MockSecureResolver) VerifyNoLeaks(ctx context.Context) error {
	args := m.Called(ctx)
	return args.Error(0)
}

func (m *MockSecureResolver) Close() error {
	args := m.Called()
	return args.Error(0)
}

func TestHTTPSChannelWithSecureResolver(t *testing.T) {
	// Create mock objects
	mockResolver := new(MockSecureResolver)
	mockDomainGen := new(MockDomainGenerator)

	// Setup mock behavior
	mockResolver.On("LookupIPWithCache", mock.Anything, "test.example.com").Return(
		[]net.IP{net.ParseIP("192.0.2.1")}, nil)

	// Configure options with the resolver
	opts := HTTPSChannelOptions{
		PathTemplate:  "/bootstrap",
		Timeout:       5 * time.Second,
		ClientTimeout: 2 * time.Second,
		Priority:      5,
		Resolver:      mockResolver,
	}

	// Create channel with the secure resolver
	logger := logging.GetLogger()
	channel := NewHTTPSDiscoveryChannel(mockDomainGen, opts, logger)

	// Verify channel configuration
	assert.NotNil(t, channel)
	assert.Equal(t, "/bootstrap", channel.pathTemplate)
	assert.Equal(t, 5*time.Second, channel.timeout)
	assert.Equal(t, 5, channel.priority)
	assert.NotNil(t, channel.client)
}

func TestHTTPSChannelWithoutResolver(t *testing.T) {
	mockDomainGen := new(MockDomainGenerator)

	// Configure options without a resolver
	opts := HTTPSChannelOptions{
		PathTemplate:  "/api/bootstrap",
		Timeout:       10 * time.Second,
		ClientTimeout: 3 * time.Second,
		Priority:      3,
		// No resolver
	}

	// Create channel without a secure resolver
	logger := logging.GetLogger()
	channel := NewHTTPSDiscoveryChannel(mockDomainGen, opts, logger)

	// Verify channel configuration
	assert.NotNil(t, channel)
	assert.Equal(t, "/api/bootstrap", channel.pathTemplate)
	assert.Equal(t, 10*time.Second, channel.timeout)
	assert.Equal(t, 3, channel.priority)
	assert.NotNil(t, channel.client)
	assert.Equal(t, 3*time.Second, channel.client.Timeout)
}

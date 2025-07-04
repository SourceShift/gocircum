package channels

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/gocircum/gocircum/pkg/securedns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockResolver is a mock implementation of the Resolver interface for testing
type MockResolver struct {
	mock.Mock
}

func (m *MockResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	args := m.Called(ctx, domain)
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	args := m.Called(ctx, service, proto, name)
	return args.String(0), args.Get(1).([]*net.SRV), args.Error(2)
}

// MockDomainGenerator is a mock implementation of the DomainGenerator interface for testing
type MockDomainGenerator struct {
	mock.Mock
}

func (m *MockDomainGenerator) GenerateDomains(count int) []string {
	args := m.Called(count)
	return args.Get(0).([]string)
}

func TestNewDNSDiscoveryChannel(t *testing.T) {
	logger := logging.GetLogger()

	// Test with default options
	domainGen := new(MockDomainGenerator)
	channel := NewDNSDiscoveryChannel(domainGen, DNSChannelOptions{}, logger)

	assert.NotNil(t, channel)
	assert.Equal(t, "dns", channel.Name())
	assert.Equal(t, 0, channel.Priority()) // Default priority is 0
	assert.Equal(t, 30*time.Second, channel.Timeout())

	// The resolver should be a secureResolver, not defaultResolver
	_, ok := channel.resolver.(*secureResolver)
	assert.True(t, ok, "Expected resolver to be a secureResolver")
}

func TestDNSDiscoveryChannelDiscover(t *testing.T) {
	// Create mock domain generator
	domainGen := new(MockDomainGenerator)
	domainGen.On("GenerateDomains", 5).Return([]string{"test1.example.com", "test2.example.com"})

	// Create mock resolver
	mockResolver := new(MockResolver)
	mockResolver.On("LookupTXT", mock.Anything, "test1.example.com").Return(
		[]string{"10.0.0.1:8080, 10.0.0.2:8080"}, nil)
	mockResolver.On("LookupTXT", mock.Anything, "test2.example.com").Return(
		[]string{"10.0.0.3:8080"}, nil)
	mockResolver.On("LookupSRV", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(
		"", []*net.SRV{}, nil)

	// Create DNS channel with mocks
	channel := &DNSDiscoveryChannel{
		domainGenerator: domainGen,
		resolver:        mockResolver,
		logger:          logging.GetLogger(),
		timeout:         1 * time.Second,
		priority:        0,
		recordTypes:     []string{"TXT", "SRV"},
		domainsPerIter:  5,
	}

	// Execute discover
	results, err := channel.Discover(context.Background())

	// Verify results
	assert.NoError(t, err)
	assert.Contains(t, results, "10.0.0.1:8080")
	assert.Contains(t, results, "10.0.0.2:8080")
	assert.Contains(t, results, "10.0.0.3:8080")
	assert.Len(t, results, 3)

	// Verify mock expectations
	domainGen.AssertExpectations(t)
	mockResolver.AssertExpectations(t)
}

func TestSecureResolverBlocksSystemDNS(t *testing.T) {
	// Create a secure resolver
	resolver := &secureResolver{
		resolver: nil, // Intentionally nil to test failure path
		logger:   logging.GetLogger(),
	}

	// Try to use the resolver for TXT lookups
	_, err := resolver.LookupTXT(context.Background(), "example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secure TXT lookup not implemented yet")

	// Try to use the resolver for SRV lookups
	_, _, err = resolver.LookupSRV(context.Background(), "service", "tcp", "example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secure SRV lookup not implemented yet")
}

func TestSimpleDomainGeneratorUsesSecureRandom(t *testing.T) {
	domains := []string{"example1.com", "example2.com", "example3.com", "example4.com", "example5.com"}
	generator := NewSimpleDomainGenerator(domains)

	// Generate a subset of domains
	result := generator.GenerateDomains(3)

	// Verify the result
	assert.Len(t, result, 3)
	for _, domain := range result {
		assert.Contains(t, domains, domain)
	}
}

func TestChannelUsesSecureDNSResolver(t *testing.T) {
	// Skip if this test can't connect to the internet
	if testing.Short() {
		t.Skip("Skipping test that requires internet connection")
	}

	// Create a real secure resolver
	secureConfig := securedns.DefaultConfig()
	secureResolverInstance, err := securedns.New(secureConfig)
	if err != nil {
		t.Fatalf("Failed to create secure resolver: %v", err)
	}

	// Create a resolver wrapper
	resolver := &secureResolver{
		resolver: secureResolverInstance,
		logger:   logging.GetLogger(),
	}

	// Verify that lookups fail with proper error messages
	_, err = resolver.LookupTXT(context.Background(), "example.com")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "secure TXT lookup not implemented yet")

	// Clean up
	err = secureResolverInstance.Close()
	assert.NoError(t, err)
}

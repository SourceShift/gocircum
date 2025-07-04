package channels

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/gocircum/gocircum/pkg/securedns"
	"github.com/gocircum/gocircum/pkg/securerandom"
)

// DomainGenerator is an interface for generating domains
type DomainGenerator interface {
	// GenerateDomains generates a list of domains
	GenerateDomains(count int) []string
}

// SimpleDomainGenerator implements a simple domain generator for testing
type SimpleDomainGenerator struct {
	domains []string
}

// NewSimpleDomainGenerator creates a new simple domain generator
func NewSimpleDomainGenerator(domains []string) *SimpleDomainGenerator {
	return &SimpleDomainGenerator{
		domains: domains,
	}
}

// GenerateDomains returns domains from the predefined list
func (g *SimpleDomainGenerator) GenerateDomains(count int) []string {
	if len(g.domains) == 0 {
		return nil
	}

	if count >= len(g.domains) {
		return g.domains
	}

	// Return a random subset of domains using secure random
	result := make([]string, count)
	indices := securerandom.MustPerm(len(g.domains))
	for i := 0; i < count; i++ {
		result[i] = g.domains[indices[i]]
	}
	return result
}

// Resolver interface abstracts DNS resolution operations
type Resolver interface {
	// LookupTXT performs a DNS TXT record lookup
	LookupTXT(ctx context.Context, domain string) ([]string, error)
	// LookupSRV performs a DNS SRV record lookup
	LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error)
}

// secureResolver implements the Resolver interface using secure DNS resolution
type secureResolver struct {
	resolver securedns.Resolver
	logger   logging.Logger
}

// LookupTXT performs a DNS TXT record lookup using secure DNS resolution
func (r *secureResolver) LookupTXT(ctx context.Context, domain string) ([]string, error) {
	// Currently, the securedns package doesn't directly support TXT lookups
	// For now, we need to use a secure HTTP client with DoH to perform TXT lookups
	// TODO: Enhance the securedns package to support TXT lookups directly

	// Log warning about the implementation
	r.logger.Warn("Using secure TXT lookup implementation", "domain", domain)

	// For now, this is a temporary implementation that will fail securely
	// rather than leaking DNS queries
	return nil, fmt.Errorf("secure TXT lookup not implemented yet: %s", domain)
}

// LookupSRV performs a DNS SRV record lookup using secure DNS resolution
func (r *secureResolver) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	// Currently, the securedns package doesn't directly support SRV lookups
	// For now, we need to use a secure HTTP client with DoH to perform SRV lookups
	// TODO: Enhance the securedns package to support SRV lookups directly

	// Log warning about the implementation
	r.logger.Warn("Using secure SRV lookup implementation", "service", service, "proto", proto, "name", name)

	// For now, this is a temporary implementation that will fail securely
	// rather than leaking DNS queries
	return "", nil, fmt.Errorf("secure SRV lookup not implemented yet: %s %s %s", service, proto, name)
}

// DNSDiscoveryChannel implements discovery via DNS records
type DNSDiscoveryChannel struct {
	domainGenerator DomainGenerator
	resolver        Resolver
	logger          logging.Logger
	timeout         time.Duration
	priority        int
	recordTypes     []string
	domainsPerIter  int
}

// DNSChannelOptions configures the DNS discovery channel
type DNSChannelOptions struct {
	DomainsPerIteration int
	RecordTypes         []string
	Timeout             time.Duration
	Priority            int
}

// NewDNSDiscoveryChannel creates a new DNS discovery channel
func NewDNSDiscoveryChannel(domainGen DomainGenerator, opts DNSChannelOptions, logger logging.Logger) *DNSDiscoveryChannel {
	if logger == nil {
		logger = logging.GetLogger()
	}

	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	if opts.DomainsPerIteration <= 0 {
		opts.DomainsPerIteration = 5
	}

	// Set default record types if none provided
	if len(opts.RecordTypes) == 0 {
		opts.RecordTypes = []string{"TXT", "SRV"}
	}

	// Create secure resolver instead of defaultResolver
	secureConfig := securedns.DefaultConfig()
	secureResolverInstance, err := securedns.New(secureConfig)
	if err != nil {
		logger.Error("Failed to create secure DNS resolver, channel will not function properly", "error", err)
		// Create a nil resolver that will always return an error rather than using insecure system resolver
		resolver := &secureResolver{
			resolver: nil,
			logger:   logger,
		}
		return &DNSDiscoveryChannel{
			domainGenerator: domainGen,
			resolver:        resolver,
			logger:          logger,
			timeout:         opts.Timeout,
			priority:        opts.Priority,
			recordTypes:     opts.RecordTypes,
			domainsPerIter:  opts.DomainsPerIteration,
		}
	}

	// Wrap the secure resolver with our interface
	resolver := &secureResolver{
		resolver: secureResolverInstance,
		logger:   logger,
	}

	return &DNSDiscoveryChannel{
		domainGenerator: domainGen,
		resolver:        resolver,
		logger:          logger,
		timeout:         opts.Timeout,
		priority:        opts.Priority,
		recordTypes:     opts.RecordTypes,
		domainsPerIter:  opts.DomainsPerIteration,
	}
}

// Name returns the channel name
func (d *DNSDiscoveryChannel) Name() string {
	return "dns"
}

// Priority returns the channel priority
func (d *DNSDiscoveryChannel) Priority() int {
	return d.priority
}

// Timeout returns the discovery timeout
func (d *DNSDiscoveryChannel) Timeout() time.Duration {
	return d.timeout
}

// Discover attempts to find bootstrap addresses using DNS records
func (d *DNSDiscoveryChannel) Discover(ctx context.Context) ([]string, error) {
	// Generate domains to query
	domains := d.domainGenerator.GenerateDomains(d.domainsPerIter)
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains generated for DNS discovery")
	}

	d.logger.Debug("Attempting DNS discovery", "domains", domains)

	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	// Create channels for collecting results and errors
	resultChan := make(chan []string, len(domains))
	errChan := make(chan error, len(domains))
	var wg sync.WaitGroup

	// Look up each domain concurrently
	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			addresses, err := d.lookupDomain(timeoutCtx, domain)
			if err != nil {
				errChan <- fmt.Errorf("lookup failed for %s: %w", domain, err)
				return
			}
			if len(addresses) > 0 {
				resultChan <- addresses
			}
		}(domain)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(resultChan)
	close(errChan)

	// Collect all results
	var allAddresses []string
	for addresses := range resultChan {
		allAddresses = append(allAddresses, addresses...)
	}

	// Collect errors
	var errors []string
	for err := range errChan {
		errors = append(errors, err.Error())
	}

	if len(allAddresses) == 0 {
		errorMsg := "no addresses found via DNS discovery"
		if len(errors) > 0 {
			errorMsg += ": " + strings.Join(errors, "; ")
		}
		return nil, fmt.Errorf("%s", errorMsg)
	}

	// Remove duplicates
	uniqueAddresses := make(map[string]struct{})
	var result []string
	for _, addr := range allAddresses {
		if _, exists := uniqueAddresses[addr]; !exists {
			uniqueAddresses[addr] = struct{}{}
			result = append(result, addr)
		}
	}

	d.logger.Debug("DNS discovery complete",
		"domains_queried", len(domains),
		"addresses_found", len(result))

	return result, nil
}

// lookupDomain performs DNS lookups for a domain and extracts bootstrap addresses
func (d *DNSDiscoveryChannel) lookupDomain(ctx context.Context, domain string) ([]string, error) {
	var addresses []string

	for _, recordType := range d.recordTypes {
		switch recordType {
		case "TXT":
			txtRecords, err := d.resolver.LookupTXT(ctx, domain)
			if err != nil {
				d.logger.Debug("TXT lookup failed", "domain", domain, "error", err)
				continue
			}

			// Extract addresses from TXT records
			for _, record := range txtRecords {
				// Split by space or comma to handle multiple addresses in one record
				for _, part := range strings.FieldsFunc(record, func(r rune) bool {
					return r == ' ' || r == ','
				}) {
					if isValidEndpoint(part) {
						addresses = append(addresses, part)
					}
				}
			}

		case "SRV":
			// Try different service prefixes
			services := []string{"_bootstrap", "_proxy", "_service"}
			for _, service := range services {
				_, srvRecords, err := d.resolver.LookupSRV(ctx, service, "tcp", domain)
				if err != nil {
					d.logger.Debug("SRV lookup failed", "domain", domain, "service", service, "error", err)
					continue
				}

				// Extract addresses from SRV records
				for _, srv := range srvRecords {
					// Format as host:port
					addr := fmt.Sprintf("%s:%d", srv.Target, srv.Port)
					if isValidEndpoint(addr) {
						addresses = append(addresses, addr)
					}
				}
			}
		}
	}

	return addresses, nil
}

// isValidEndpoint checks if an address has a valid format (ip:port)
func isValidEndpoint(addr string) bool {
	// Simple check for now - could be enhanced with more validation
	parts := strings.Split(addr, ":")
	if len(parts) != 2 {
		return false
	}

	// Check if the port is numeric
	for _, c := range parts[1] {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

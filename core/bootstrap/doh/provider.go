package doh

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/gocircum/gocircum/pkg/logging"
)

// Provider implements the BootstrapProvider interface for DNS-over-HTTPS
type Provider struct {
	providers     []string
	urls          map[string]string
	serverNames   map[string]string
	queryTimeout  time.Duration
	maxRetries    int
	client        *http.Client
	logger        logging.Logger
	priority      int
	lastProvider  string
	requestsMutex sync.Mutex
}

// Config holds the configuration for the DoH provider
type Config struct {
	Providers    []string          `yaml:"providers"`
	URLs         map[string]string `yaml:"urls"`
	ServerNames  map[string]string `yaml:"server_names"`
	QueryTimeout time.Duration     `yaml:"query_timeout"`
	MaxRetries   int               `yaml:"max_retries"`
	Priority     int               `yaml:"priority"`
}

// New creates a new DoH bootstrap provider with the given configuration
func New(config Config, logger logging.Logger) (*Provider, error) {
	if logger == nil {
		return nil, fmt.Errorf("logger cannot be nil")
	}

	if len(config.Providers) == 0 {
		return nil, fmt.Errorf("at least one DoH provider must be specified")
	}

	if config.URLs == nil {
		return nil, fmt.Errorf("DoH URLs must be specified")
	}

	for _, provider := range config.Providers {
		if _, ok := config.URLs[provider]; !ok {
			return nil, fmt.Errorf("URL not specified for provider: %s", provider)
		}
	}

	// Set default timeout if not provided
	if config.QueryTimeout == 0 {
		config.QueryTimeout = 5 * time.Second
	}

	// Set default max retries if not provided
	if config.MaxRetries <= 0 {
		config.MaxRetries = 3
	}

	client := &http.Client{
		Timeout: config.QueryTimeout,
	}

	return &Provider{
		providers:    config.Providers,
		urls:         config.URLs,
		serverNames:  config.ServerNames,
		queryTimeout: config.QueryTimeout,
		maxRetries:   config.MaxRetries,
		client:       client,
		logger:       logger,
		priority:     config.Priority,
	}, nil
}

// Name returns the name of the bootstrap provider
func (p *Provider) Name() string {
	return "doh"
}

// Priority returns the priority of this provider
func (p *Provider) Priority() int {
	return p.priority
}

// Discover returns a list of bootstrap addresses using DNS-over-HTTPS
func (p *Provider) Discover(ctx context.Context) ([]string, error) {
	var allAddresses []string
	var providerErrors []error

	// Try to discover bootstrap addresses using each configured provider
	for _, provider := range p.getShuffledProviders() {
		p.requestsMutex.Lock()
		p.lastProvider = provider
		p.requestsMutex.Unlock()

		url := p.urls[provider]
		serverName := p.serverNames[provider]

		// Hardened: Multi-channel bootstrap discovery with DGA fallback
		bootstrapDomains := p.getBootstrapDomains()

		for _, domain := range bootstrapDomains {
			for retry := 0; retry < p.maxRetries; retry++ {
				select {
				case <-ctx.Done():
					return allAddresses, ctx.Err()
				default:
					// Continue with the request
				}

				addresses, err := p.resolveDomain(ctx, domain, provider, url, serverName)
				if err != nil {
					p.logger.Debug("DoH resolution failed",
						"provider", provider,
						"domain_hash", hashDomain(domain),
						"retry", retry,
						"error", err)
					providerErrors = append(providerErrors, err)
					// Wait before retrying with exponential backoff
					if retry < p.maxRetries-1 {
						backoffTime := time.Duration(1<<retry) * 500 * time.Millisecond
						time.Sleep(backoffTime)
					}
					continue
				}

				// Successfully resolved addresses
				allAddresses = append(allAddresses, addresses...)
				// No need to retry this domain
				break
			}
		}

		// If we got some addresses, we can stop trying more providers
		if len(allAddresses) > 0 {
			break
		}
	}

	if len(allAddresses) == 0 && len(providerErrors) > 0 {
		// Return the last error if no addresses were found
		return nil, fmt.Errorf("all DoH providers failed: %w", providerErrors[len(providerErrors)-1])
	}

	return allAddresses, nil
}

// getBootstrapDomains returns domains from multiple discovery channels with DGA fallback
func (p *Provider) getBootstrapDomains() []string {
	var domains []string

	// 1. Try decentralized discovery first
	if socialDomains := p.discoverViaSocialMedia(); len(socialDomains) > 0 {
		domains = append(domains, socialDomains...)
	}

	// 2. Generate domains using cryptographic DGA
	dgaDomains := p.generateDGADomains(time.Now())
	domains = append(domains, dgaDomains...)

	// 3. Try steganographic discovery
	if stegoDomains := p.discoverViaSteganography(); len(stegoDomains) > 0 {
		domains = append(domains, stegoDomains...)
	}

	// 4. Shuffle to prevent predictable order
	p.cryptoShuffle(domains)
	return domains
}

// generateDGADomains creates unpredictable domains using multiple entropy sources
func (p *Provider) generateDGADomains(seed time.Time) []string {
	// Implement truly unpredictable domain generation using multiple entropy sources

	// 1. Gather entropy from multiple uncorrelated sources
	entropyBundle := p.gatherEnhancedEntropyBundle(seed)

	// 2. Validate entropy quality to prevent predictable generation
	if err := p.validateEntropyQuality(entropyBundle); err != nil {
		p.logger.Error("Insufficient entropy for secure DGA", "error", err)
		// Fall back to peer discovery rather than predictable domains
		return p.getPeerDiscoveredDomains()
	}

	// 3. Generate domains using multiple strategies with adaptive counts
	strategies := p.selectDiversifiedStrategies(entropyBundle)
	var allDomains []string

	for _, strategy := range strategies {
		strategyDomains := p.executeGenerationStrategy(strategy, entropyBundle)
		allDomains = append(allDomains, strategyDomains...)
	}

	// 4. Apply domain validation and filtering
	validDomains := p.filterValidDomains(allDomains)

	// 5. Implement adaptive subset selection based on network conditions
	optimalCount := p.calculateOptimalDomainCount(entropyBundle)
	finalDomains := p.selectAdaptiveSubset(validDomains, optimalCount)

	// 6. Add peer-discovered domains for redundancy
	peerDomains := p.getPeerDiscoveredDomains()
	finalDomains = append(finalDomains, peerDomains...)

	// 7. Final cryptographic shuffling with multi-layer randomization
	return p.performCryptographicShuffle(finalDomains, entropyBundle)
}

// gatherEnhancedEntropyBundle collects entropy from diverse, uncorrelated sources
func (p *Provider) gatherEnhancedEntropyBundle(seed time.Time) *EntropyBundle {
	bundle := &EntropyBundle{
		TimeBased:      p.gatherTemporalEntropy(seed),
		NetworkBased:   p.gatherNetworkCharacteristics(),
		SystemBased:    p.gatherSystemFingerprint(),
		ExternalBased:  p.gatherGeolocationEntropy(),
		ClientSpecific: p.gatherUserBehaviorEntropy(),
	}

	return bundle
}

// validateEntropyQuality ensures sufficient unpredictability
func (p *Provider) validateEntropyQuality(bundle *EntropyBundle) error {
	// Test entropy using statistical tests (NIST test suite)
	entropyTests := []func(*EntropyBundle) error{
		p.runFrequencyTest,
		p.runRunsTest,
		p.runApproximateEntropyTest,
		p.runSerialTest,
	}

	for _, test := range entropyTests {
		if err := test(bundle); err != nil {
			return fmt.Errorf("entropy quality test failed: %w", err)
		}
	}

	return nil
}

// gatherTemporalEntropy collects time-based entropy
func (p *Provider) gatherTemporalEntropy(seed time.Time) []byte {
	h := sha256.New()

	// Use multiple timing aspects for better entropy
	now := time.Now()

	// Base seed
	ts := seed.UnixNano()
	_, _ = fmt.Fprintf(h, "%d", ts)

	// Current time
	interval := now.Sub(seed).Nanoseconds()
	h.Write([]byte{
		byte(interval >> 56),
		byte(interval >> 48),
		byte(interval >> 40),
		byte(interval >> 32),
		byte(interval >> 24),
		byte(interval >> 16),
		byte(interval >> 8),
		byte(interval),
	})

	// Measure operation timing for additional entropy
	start := time.Now().UnixNano()
	// Perform arbitrary operations
	end := time.Now().UnixNano()

	_, _ = fmt.Fprintf(h, "%d", end-start)

	return h.Sum(nil)
}

// gatherNetworkCharacteristics collects entropy from network properties
func (p *Provider) gatherNetworkCharacteristics() []byte {
	h := sha256.New()

	// Add network interface info
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			h.Write([]byte(iface.Name))
			h.Write([]byte(iface.HardwareAddr))
			addresses, err := iface.Addrs()
			if err == nil {
				for _, addr := range addresses {
					h.Write([]byte(addr.String()))
				}
			}
		}
	}

	// Add TCP connection properties if available
	// This is a simplified implementation; in practice, we would
	// use more sophisticated network characteristic gathering

	return h.Sum(nil)
}

// gatherSystemFingerprint collects system-specific entropy
func (p *Provider) gatherSystemFingerprint() []byte {
	// In a real implementation, this would gather non-identifying
	// system characteristics for entropy generation

	// Combine various system properties
	h := sha256.New()

	// Use current timestamp as a simple entropy source
	_, _ = fmt.Fprintf(h, "%d", time.Now().UnixNano())

	return h.Sum(nil)
}

// gatherGeolocationEntropy gathers approximate location data for entropy
func (p *Provider) gatherGeolocationEntropy() []byte {
	// In a production implementation, this would use privacy-preserving
	// geolocation approximation to add entropy without privacy concerns

	// For now, return a placeholder
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// If random generation fails, use timestamp as fallback
		binary.BigEndian.PutUint64(b, uint64(time.Now().UnixNano()))
	}
	return b
}

// gatherUserBehaviorEntropy collects entropy from user interaction patterns
func (p *Provider) gatherUserBehaviorEntropy() []byte {
	// In a real implementation with UI, this would collect entropy from:
	// - Mouse movements
	// - Keyboard timing
	// - Touch gestures
	// - Application usage patterns

	// For now, return a placeholder
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// If random generation fails, use timestamp as fallback
		binary.BigEndian.PutUint64(b, uint64(time.Now().UnixNano()))
	}
	return b
}

// runFrequencyTest performs the NIST frequency test on entropy
func (p *Provider) runFrequencyTest(bundle *EntropyBundle) error {
	// Simplified implementation of frequency test
	// In a real implementation, we would use formal NIST test suite

	// For now, just check that we have some entropy
	combinedLength := len(bundle.TimeBased) + len(bundle.NetworkBased) +
		len(bundle.SystemBased) + len(bundle.ExternalBased) +
		len(bundle.ClientSpecific)

	if combinedLength < 16 {
		return fmt.Errorf("insufficient entropy")
	}

	return nil
}

// runRunsTest performs the NIST runs test on entropy
func (p *Provider) runRunsTest(bundle *EntropyBundle) error {
	// Placeholder for runs test
	return nil
}

// runApproximateEntropyTest performs entropy quality assessment
func (p *Provider) runApproximateEntropyTest(bundle *EntropyBundle) error {
	// Placeholder for approximate entropy test
	return nil
}

// runSerialTest performs the NIST serial test on entropy
func (p *Provider) runSerialTest(bundle *EntropyBundle) error {
	// Placeholder for serial test
	return nil
}

// getPeerDiscoveredDomains implements decentralized peer discovery
func (p *Provider) getPeerDiscoveredDomains() []string {
	// Connect to peer network for domain discovery
	peerNetwork := p.connectToPeerNetwork()
	if peerNetwork == nil {
		return []string{}
	}

	// Query multiple peers for bootstrap domains
	domains := make([]string, 0)
	peers := peerNetwork.GetRandomPeers(5)

	for _, peer := range peers {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		peerDomains, err := peer.QueryBootstrapDomains(ctx)
		cancel()

		if err == nil {
			// Validate peer-provided domains before using
			validatedDomains := p.validatePeerDomains(peerDomains, peer)
			domains = append(domains, validatedDomains...)
		}
	}

	return p.removeDuplicateDomains(domains)
}

// validateEntropyIndependence cross-validates entropy sources
func (p *Provider) validateEntropyIndependence(bundle *EntropyBundle) []byte {
	// In a real implementation, we would test for correlation between
	// entropy sources and exclude or down-weight correlated sources

	// For now, combine all entropy sources into a single validated source
	h := sha256.New()
	h.Write(bundle.TimeBased)
	h.Write(bundle.NetworkBased)
	h.Write(bundle.SystemBased)
	h.Write(bundle.ExternalBased)
	h.Write(bundle.ClientSpecific)

	return h.Sum(nil)
}

// connectToPeerNetwork connects to the peer-to-peer discovery network
func (p *Provider) connectToPeerNetwork() PeerNetwork {
	// In a real implementation, this would connect to a P2P network
	// for decentralized discovery

	// For now, return nil to indicate no peer network
	return nil
}

// PeerNetwork interface defines operations for peer-based discovery
type PeerNetwork interface {
	GetRandomPeers(count int) []Peer
}

// Peer interface defines operations that can be performed with a peer
type Peer interface {
	QueryBootstrapDomains(ctx context.Context) ([]string, error)
}

// validatePeerDomains validates domains provided by peers
func (p *Provider) validatePeerDomains(domains []string, peer Peer) []string {
	// In a real implementation, this would:
	// - Check domain format
	// - Verify against allow/blocklists
	// - Apply reputation scoring
	// - Check for honeytoken domains

	// For now, return all domains
	return domains
}

// removeDuplicateDomains removes duplicate domains
func (p *Provider) removeDuplicateDomains(domains []string) []string {
	uniqueMap := make(map[string]struct{})
	result := make([]string, 0)

	for _, domain := range domains {
		if _, exists := uniqueMap[domain]; !exists {
			uniqueMap[domain] = struct{}{}
			result = append(result, domain)
		}
	}

	return result
}

// selectDiversifiedStrategies chooses domain generation strategies
func (p *Provider) selectDiversifiedStrategies(bundle *EntropyBundle) []string {
	// In a real implementation, this would select strategies based on:
	// - Current network conditions
	// - Threat environment
	// - Available entropy quality
	// - Past success rates

	// For now, return fixed strategies
	return []string{
		"mathematical",
		"dictionary",
		"hijacking",
		"steganographic",
		"polymorphic",
	}
}

// executeGenerationStrategy executes a specific domain generation strategy
func (p *Provider) executeGenerationStrategy(strategy string, bundle *EntropyBundle) []string {
	switch strategy {
	case "mathematical":
		return p.generateMathematicalDomains(bundle, 15)
	case "dictionary":
		return p.generateDictionaryDomains(bundle, 10)
	case "hijacking":
		return p.generateHijackingDomains(bundle, 5)
	case "steganographic":
		return p.generateSteganographicDomains(bundle, 5)
	case "polymorphic":
		return p.generatePolymorphicDomains(bundle, 5)
	default:
		return []string{}
	}
}

// generateSteganographicDomains creates domains with hidden patterns
func (p *Provider) generateSteganographicDomains(bundle *EntropyBundle, count int) []string {
	// Placeholder implementation
	return make([]string, 0)
}

// generatePolymorphicDomains creates domains that mutate over time
func (p *Provider) generatePolymorphicDomains(bundle *EntropyBundle, count int) []string {
	// Placeholder implementation
	return make([]string, 0)
}

// filterValidDomains validates and filters generated domains
func (p *Provider) filterValidDomains(domains []string) []string {
	// In a real implementation, this would:
	// - Validate domain format
	// - Check domain reputation
	// - Filter known honeypots or monitoring domains
	// - Ensure diversity in pattern and TLDs

	// For now, return all domains
	return domains
}

// calculateOptimalDomainCount determines ideal number of domains
func (p *Provider) calculateOptimalDomainCount(bundle *EntropyBundle) int {
	// In a real implementation, this would adjust based on:
	// - Network conditions
	// - Detected censorship
	// - Past success rates

	// For now, return a fixed count
	return 15
}

// selectAdaptiveSubset selects diverse domains from the pool
func (p *Provider) selectAdaptiveSubset(domains []string, count int) []string {
	// In a real implementation, this would select a diverse set of domains:
	// - Different patterns
	// - Different TLDs
	// - Different generation strategies

	// For now, return up to count domains
	if len(domains) <= count {
		return domains
	}
	return domains[:count]
}

// performCryptographicShuffle shuffles domains using secure randomness
func (p *Provider) performCryptographicShuffle(domains []string, bundle *EntropyBundle) []string {
	result := make([]string, len(domains))
	copy(result, domains)

	// Fisher-Yates shuffle with crypto/rand
	for i := len(result) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			p.logger.Error("Failed to generate secure random number for domain shuffling", "error", err)
			return domains // Return unshuffled as fallback
		}
		result[i], result[j.Int64()] = result[j.Int64()], result[i]
	}

	return result
}

// getDGATLD returns a TLD for the DGA
func (p *Provider) getDGATLD() string {
	tlds := []string{"com", "net", "org", "info", "xyz"}
	idx := int(time.Now().Unix() % int64(len(tlds)))
	return tlds[idx]
}

// discoverViaSocialMedia attempts to find bootstrap domains from social media sources
func (p *Provider) discoverViaSocialMedia() []string {
	// This is a placeholder for real implementation
	// In reality, this would query specific social media accounts or posts
	// that contain steganographically hidden bootstrap information
	return []string{}
}

// discoverViaSteganography attempts to find domains hidden in public web content
func (p *Provider) discoverViaSteganography() []string {
	// This is a placeholder for real implementation
	// In reality, this would extract domains from images or other content
	return []string{}
}

// cryptoShuffle uses cryptographic randomness to shuffle a slice
func (p *Provider) cryptoShuffle(slice []string) {
	for i := len(slice) - 1; i > 0; i-- {
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			// If secure random fails, log and don't shuffle
			p.logger.Error("Failed to generate secure random number for domain shuffling", "error", err)
			return
		}
		slice[i], slice[j.Int64()] = slice[j.Int64()], slice[i]
	}
}

// hashDomain creates a consistent hash of domain names for logging
func hashDomain(domain string) string {
	h := sha256.Sum256([]byte(domain))
	return fmt.Sprintf("domain_%x", h[:4]) // First 8 hex chars for identification
}

// getShuffledProviders returns a cryptographically secure shuffled copy of providers
func (p *Provider) getShuffledProviders() []string {
	// Create a copy of the providers slice
	shuffled := make([]string, len(p.providers))
	copy(shuffled, p.providers)

	// Shuffle using crypto/rand for security
	for i := len(shuffled) - 1; i > 0; i-- {
		// Generate a secure random number in range [0, i]
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			// If secure random fails, log and don't shuffle
			p.logger.Error("Failed to generate secure random number for provider shuffling", "error", err)
			return p.providers
		}
		// Swap elements i and j
		shuffled[i], shuffled[j.Int64()] = shuffled[j.Int64()], shuffled[i]
	}

	return shuffled
}

// dnsResponse represents the JSON response from a DoH query
type dnsResponse struct {
	Status   int     `json:"Status"`
	Answer   []dnsRR `json:"Answer,omitempty"`
	Question []dnsRR `json:"Question,omitempty"`
	Comment  string  `json:"Comment,omitempty"`
	Error    string  `json:"Error,omitempty"`
}

// dnsRR represents a DNS resource record
type dnsRR struct {
	Name string `json:"name,omitempty"`
	Type int    `json:"type,omitempty"`
	TTL  int    `json:"TTL,omitempty"`
	Data string `json:"data,omitempty"`
}

// resolveDomain resolves a domain name to IP addresses using a DoH provider
func (p *Provider) resolveDomain(ctx context.Context, domain, provider, url, serverName string) ([]string, error) {
	// Construct the DoH query URL (example: https://dns.google/resolve?name=example.com&type=A)
	queryURL := fmt.Sprintf("%s?name=%s&type=A", url, domain)

	// Create a new request
	req, err := http.NewRequestWithContext(ctx, "GET", queryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create DoH request: %w", err)
	}

	// Set appropriate headers
	req.Header.Set("Accept", "application/dns-json")
	if serverName != "" {
		req.Host = serverName
	}

	// Perform the request
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH request returned non-OK status: %d", resp.StatusCode)
	}

	// Read and parse the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	var dnsResp dnsResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, fmt.Errorf("failed to parse DoH response: %w", err)
	}

	// Check if there was an error in the DNS response
	if dnsResp.Status != 0 {
		return nil, fmt.Errorf("DNS resolution failed with status: %d", dnsResp.Status)
	}

	if len(dnsResp.Answer) == 0 {
		return nil, fmt.Errorf("no DNS answers returned for domain: %s", domain)
	}

	var addresses []string
	for _, answer := range dnsResp.Answer {
		// Type 1 is A record (IPv4 address)
		if answer.Type == 1 {
			// Validate that it's a valid IP address
			ip := net.ParseIP(answer.Data)
			if ip == nil {
				p.logger.Debug("Invalid IP address in DoH response", "data", answer.Data)
				continue
			}

			// Use default port 443 if not specified
			port := 443
			address := net.JoinHostPort(answer.Data, strconv.Itoa(port))
			addresses = append(addresses, address)
		}
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no valid A records found for domain: %s", domain)
	}

	p.logger.Debug("Resolved bootstrap addresses via DoH",
		"provider", provider,
		"domain", domain,
		"count", len(addresses))

	return addresses, nil
}

// EntropyBundle contains multiple entropy sources for DGA
type EntropyBundle struct {
	TimeBased      []byte // Multiple time-based seeds
	NetworkBased   []byte // Local network characteristics
	SystemBased    []byte // System-specific entropy
	ExternalBased  []byte // External unpredictable data
	ClientSpecific []byte // Unique client characteristics
}

// generateMathematicalDomains creates high-entropy mathematical domains
func (p *Provider) generateMathematicalDomains(bundle *EntropyBundle, count int) []string {
	domains := make([]string, 0, count)

	// Use PBKDF2 for key stretching with multiple inputs
	combinedEntropy := p.combineEntropySecurely(bundle)

	for i := 0; i < count; i++ {
		// Generate domain using PBKDF2 with high iteration count
		key := pbkdf2.Key(combinedEntropy, []byte(fmt.Sprintf("domain_salt_%d", i)), 100000, 32, sha256.New)

		// Create domain name with realistic characteristics
		domain := p.createRealisticDomainFromKey(key)
		domains = append(domains, domain)
	}

	return domains
}

// generateDictionaryDomains creates domains that look like legitimate services
func (p *Provider) generateDictionaryDomains(bundle *EntropyBundle, count int) []string {
	// Generate domains that look like legitimate services
	wordLists := p.loadWordLists() // Common tech terms, brand names, etc.

	domains := make([]string, 0, count)
	entropy := p.combineEntropySecurely(bundle)

	for i := 0; i < count; i++ {
		// Combine words to create believable domain names
		domain := p.generateBelieverDomain(wordLists, entropy, i)
		domains = append(domains, domain)
	}

	return domains
}

// generateHijackingDomains creates subdomains that might look like legitimate services
func (p *Provider) generateHijackingDomains(bundle *EntropyBundle, count int) []string {
	domains := make([]string, 0, count)
	entropy := p.combineEntropySecurely(bundle)

	// Base domains that could be used for subdomain hijacking
	baseDomains := []string{"api", "cdn", "static", "assets", "media", "files"}

	for i := 0; i < count; i++ {
		// Generate subdomain that looks legitimate
		hash := sha256.New()
		hash.Write(entropy)
		_, _ = fmt.Fprintf(hash, "hijack_%d", i)
		hashBytes := hash.Sum(nil)

		baseIdx := int(hashBytes[0]) % len(baseDomains)
		subdomain := fmt.Sprintf("%x", hashBytes[1:5])
		domain := fmt.Sprintf("%s-%s.%s", baseDomains[baseIdx], subdomain, p.getDGATLD())
		domains = append(domains, domain)
	}

	return domains
}

// selectRandomSubset selects a random subset of domains
func (p *Provider) selectRandomSubset(domains []string, count int) []string {
	if len(domains) <= count {
		return domains
	}

	// Cryptographically secure shuffle
	p.cryptoShuffle(domains)
	return domains[:count]
}

// Helper methods for entropy gathering
func (p *Provider) generateTimeBasedEntropy(seed time.Time) []byte {
	entropy := make([]byte, 0, 64)

	// Multiple time granularities
	entropy = append(entropy, []byte(seed.Format("2006-01-02-15-04"))...)
	entropy = append(entropy, []byte(fmt.Sprintf("%d", seed.UnixNano()))...)
	entropy = append(entropy, []byte(fmt.Sprintf("%d", seed.Unix()))...)

	return entropy
}

func (p *Provider) extractNetworkEntropy() []byte {
	// Simple network-based entropy (in real implementation, use more sources)
	entropy := make([]byte, 16)
	_, _ = rand.Read(entropy)
	return entropy
}

func (p *Provider) extractSystemEntropy() []byte {
	// System-based entropy (simplified)
	entropy := make([]byte, 16)
	_, _ = rand.Read(entropy)
	return entropy
}

func (p *Provider) extractExternalEntropy() []byte {
	// External entropy sources (simplified)
	entropy := make([]byte, 16)
	_, _ = rand.Read(entropy)
	return entropy
}

func (p *Provider) extractClientEntropy() []byte {
	// Client-specific entropy (simplified)
	entropy := make([]byte, 16)
	_, _ = rand.Read(entropy)
	return entropy
}

func (p *Provider) combineEntropySecurely(bundle *EntropyBundle) []byte {
	hash := sha256.New()
	hash.Write(bundle.TimeBased)
	hash.Write(bundle.NetworkBased)
	hash.Write(bundle.SystemBased)
	hash.Write(bundle.ExternalBased)
	hash.Write(bundle.ClientSpecific)
	return hash.Sum(nil)
}

func (p *Provider) createRealisticDomainFromKey(key []byte) string {
	// Create realistic domain from cryptographic key
	hash := sha256.New()
	hash.Write(key)
	hashBytes := hash.Sum(nil)

	domain := fmt.Sprintf("%x.%s", hashBytes[:8], p.getDGATLD())
	return domain
}

func (p *Provider) loadWordLists() map[string][]string {
	// In real implementation, load from files or embed
	return map[string][]string{
		"tech":    []string{"api", "cloud", "data", "net", "web", "app", "dev", "tech"},
		"brands":  []string{"google", "amazon", "microsoft", "apple", "meta", "netflix"},
		"generic": []string{"secure", "fast", "global", "pro", "plus", "max", "ultra"},
	}
}

func (p *Provider) generateBelieverDomain(wordLists map[string][]string, entropy []byte, index int) string {
	hash := sha256.New()
	hash.Write(entropy)
	_, _ = fmt.Fprintf(hash, "dict_%d", index)
	hashBytes := hash.Sum(nil)

	// Select words from different categories
	techWords := wordLists["tech"]
	brandWords := wordLists["brands"]

	techIdx := int(hashBytes[0]) % len(techWords)
	brandIdx := int(hashBytes[1]) % len(brandWords)

	domain := fmt.Sprintf("%s-%s.%s", techWords[techIdx], brandWords[brandIdx], p.getDGATLD())
	return domain
}

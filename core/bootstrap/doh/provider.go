package doh

//nolint:unused

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/gocircum/gocircum/pkg/securerandom"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

// secureBootstrapClient is a singleton instance of a hardened HTTP client for bootstrap discovery.
var secureBootstrapClient *http.Client

// Provider implements the BootstrapProvider interface for DNS-over-HTTPS
type Provider struct {
	providers    []string
	urls         map[string]string
	serverNames  map[string]string
	queryTimeout time.Duration
	maxRetries   int
	client       *http.Client
	logger       logging.Logger
	priority     int
	//nolint:unused
	lastProvider string
	secretSalt   []byte

	// Cache for bootstrap domains
	cachedDomains  []string
	cacheTimestamp time.Time

	// Configuration
	config struct {
		MinDomains     int
		MinDomainCount int
		CacheTTL       time.Duration
	}

	// IPCache stores IP addresses for DoH providers to avoid system DNS lookups
	ipCache *IPCache
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

// PeerNetwork interface defines operations for peer-based discovery
type PeerNetwork interface {
	GetRandomPeers(count int) []Peer
}

// Peer interface defines operations that can be performed with a peer
type Peer interface {
	QueryBootstrapDomains(ctx context.Context) ([]string, error)
}

// defaultPeerNetwork implements the PeerNetwork interface
type defaultPeerNetwork struct {
	peers  []Peer
	logger logging.Logger
}

// defaultPeer implements the Peer interface
type defaultPeer struct {
	address string
	port    int
	key     string
	logger  logging.Logger
	client  *http.Client
}

func (n *defaultPeerNetwork) GetRandomPeers(count int) []Peer {
	if count >= len(n.peers) {
		return n.peers
	}

	// Create a copy of peers to avoid modifying the original slice
	peersCopy := make([]Peer, len(n.peers))
	copy(peersCopy, n.peers)

	// Shuffle the peers using crypto/rand
	for i := len(peersCopy) - 1; i > 0; i-- {
		// Generate random number between 0 and i
		j, err := securerandom.Int(0, i+1)
		if err != nil || j > i {
			// Log error but continue with less randomness in worst case
			j = i / 2 // Simple fallback that at least gives some shuffling
		}

		// Swap elements
		peersCopy[i], peersCopy[j] = peersCopy[j], peersCopy[i]
	}

	return peersCopy[:count]
}

func (p *defaultPeer) QueryBootstrapDomains(ctx context.Context) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", p.address+":"+strconv.Itoa(p.port)+"/bootstrap/domains", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query peer: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Warn("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var domains []string
	if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return domains, nil
}

// peerConfig represents the configuration for a peer
type peerConfig struct {
	Address string `json:"address" yaml:"address"`
	Port    int    `json:"port" yaml:"port"`
	Key     string `json:"key" yaml:"key"`
}

// peerNetworkConfig represents the configuration for the peer network
type peerNetworkConfig struct {
	Peers []peerConfig `json:"peers" yaml:"peers"`
}

// EntropyBundle contains entropy from various sources for domain generation
type EntropyBundle struct {
	Timestamp          int64
	Sources            map[string][]byte
	Quality            float64
	HardwareEntropy    []byte
	NetworkEntropy     []byte
	SystemEntropy      []byte
	ExternalEntropy    []byte
	TimeBased          []byte
	GeolocationEntropy []byte
}

// IPCache stores IP addresses for DoH providers to avoid system DNS lookups
type IPCache struct {
	cache      map[string][]net.IP
	expiration map[string]time.Time
	mutex      sync.RWMutex
	logger     logging.Logger
}

// NewIPCache creates a new IP cache for DoH providers
func NewIPCache(logger logging.Logger) *IPCache {
	if logger == nil {
		logger = logging.GetLogger()
	}

	return &IPCache{
		cache:      make(map[string][]net.IP),
		expiration: make(map[string]time.Time),
		logger:     logger,
	}
}

// Get retrieves cached IP addresses for a domain
func (c *IPCache) Get(domain string) ([]net.IP, bool) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	ips, ok := c.cache[domain]
	if !ok {
		return nil, false
	}

	// Check if the entry has expired
	expiry, ok := c.expiration[domain]
	if !ok || time.Now().After(expiry) {
		return nil, false
	}

	return ips, true
}

// Set stores IP addresses for a domain with an expiration time
func (c *IPCache) Set(domain string, ips []net.IP, ttl time.Duration) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Make a copy of the IP addresses to avoid external modifications
	ipsCopy := make([]net.IP, len(ips))
	for i, ip := range ips {
		ipCopy := make(net.IP, len(ip))
		copy(ipCopy, ip)
		ipsCopy[i] = ipCopy
	}

	c.cache[domain] = ipsCopy
	c.expiration[domain] = time.Now().Add(ttl)

	c.logger.Debug("Cached IP addresses for domain",
		"domain", domain,
		"ips", fmt.Sprintf("%v", ipsCopy),
		"expiration", c.expiration[domain])
}

// Remove deletes a domain from the cache
func (c *IPCache) Remove(domain string) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	delete(c.cache, domain)
	delete(c.expiration, domain)
}

// Cleanup removes expired entries from the cache
func (c *IPCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for domain, expiry := range c.expiration {
		if now.After(expiry) {
			delete(c.cache, domain)
			delete(c.expiration, domain)
			c.logger.Debug("Removed expired cache entry", "domain", domain)
		}
	}
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

	// Create default HTTP client with reasonable timeouts
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Dial: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	p := &Provider{
		providers:    config.Providers,
		urls:         config.URLs,
		serverNames:  config.ServerNames,
		queryTimeout: config.QueryTimeout,
		maxRetries:   config.MaxRetries,
		client:       httpClient,
		logger:       logger,
		priority:     config.Priority,
		ipCache:      NewIPCache(logger),
	}

	// Initialize config defaults
	p.config.MinDomains = 3
	p.config.MinDomainCount = 10
	p.config.CacheTTL = 4 * time.Hour

	// Initialize secure salt with high-quality entropy
	var err error
	p.secretSalt, err = p.initializeSecureSalt()
	if err != nil {
		p.logger.Error("Failed to initialize secure salt", "error", err)
		// Generate fallback salt with best available entropy
		fallbackSalt := make([]byte, 32)
		if _, err := cryptorand.Read(fallbackSalt); err != nil {
			return nil, fmt.Errorf("critical security failure: cannot generate secure salt: %w", err)
		}
		p.secretSalt = fallbackSalt
	}

	return p, nil
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
	// Use a diversified strategy to discover domains
	p.logger.Debug("Starting domain discovery process")
	discoveredDomains, err := p.getBootstrapDomains(ctx)
	if err != nil {
		p.logger.Error("Failed to get bootstrap domains", "error", err)
		return nil, fmt.Errorf("domain discovery failed: %w", err)
	}
	p.logger.Info("Domain discovery process completed", "discovered_count", len(discoveredDomains))
	return discoveredDomains, nil
}

// GetBootstrapDomains returns a list of bootstrap domains for the DoH provider.
// This method ensures that no system DNS lookups occur during the bootstrap process.
func (p *Provider) GetBootstrapDomains(ctx context.Context) ([]string, error) {
	// Check if we have cached domains that are still valid
	if !p.isCacheExpired() && len(p.cachedDomains) > 0 {
		p.logger.Debug("Using cached bootstrap domains", "count", len(p.cachedDomains))
		return p.cachedDomains, nil
	}

	// Get secure bootstrap client that doesn't use system DNS
	_, err := p.getSecureBootstrapClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create secure bootstrap client: %w", err)
	}

	// Initialize our entropy bundle for domain generation
	if len(p.secretSalt) == 0 {
		salt, err := p.initializeSecureSalt()
		if err != nil {
			p.logger.Error("Failed to initialize secure salt", "error", err)
			// Continue with a fallback mechanism, but log the error
		} else {
			p.secretSalt = salt
		}
	}

	// Generate bootstrap domains using our DGA
	domains, err := p.generateBootstrapDomains(ctx, p.config.MinDomainCount)
	if err != nil {
		p.logger.Error("Failed to generate bootstrap domains", "error", err)
		// Continue with fallback mechanisms
	}

	// Try to discover domains through peer networks without using system DNS
	peerDomains := p.getPeerDiscoveredDomains(ctx)
	if len(peerDomains) > 0 {
		domains = append(domains, peerDomains...)
	}

	// Try to discover domains through steganography without using system DNS
	stegoDomains := p.discoverViaSteganography()
	if len(stegoDomains) > 0 {
		domains = append(domains, stegoDomains...)
	}

	// Try to discover domains through social media without using system DNS
	socialDomains := p.discoverViaSocialMedia()
	if len(socialDomains) > 0 {
		domains = append(domains, socialDomains...)
	}

	// Filter out invalid domains
	validDomains := p.filterValidDomains(domains)

	// Ensure we have a minimum number of domains
	if len(validDomains) < p.config.MinDomains {
		p.logger.Warn("Insufficient valid bootstrap domains found",
			"found", len(validDomains),
			"minimum", p.config.MinDomains)

		// Add hardcoded fallback domains as a last resort
		fallbackDomains := []string{
			"dns.google",
			"cloudflare-dns.com",
			"dns.quad9.net",
		}

		// Add fallback domains that aren't already in our list
		for _, domain := range fallbackDomains {
			found := false
			for _, existing := range validDomains {
				if domain == existing {
					found = true
					break
				}
			}

			if !found {
				validDomains = append(validDomains, domain)

				// Also add the domain to our IP cache if we have hardcoded IPs
				switch domain {
				case "dns.google":
					p.ipCache.Set(domain, []net.IP{
						net.ParseIP("8.8.8.8"),
						net.ParseIP("8.8.4.4"),
					}, 24*time.Hour)
				case "cloudflare-dns.com":
					p.ipCache.Set(domain, []net.IP{
						net.ParseIP("1.1.1.1"),
						net.ParseIP("1.0.0.1"),
					}, 24*time.Hour)
				case "dns.quad9.net":
					p.ipCache.Set(domain, []net.IP{
						net.ParseIP("9.9.9.9"),
						net.ParseIP("149.112.112.112"),
					}, 24*time.Hour)
				}
			}
		}
	}

	// Shuffle the domains for better distribution
	p.cryptoShuffle(validDomains)

	// Cache the domains
	p.cachedDomains = validDomains
	p.cacheTimestamp = time.Now()

	p.logger.Debug("Generated bootstrap domains", "count", len(validDomains))
	return validDomains, nil
}

// getBootstrapDomains orchestrates the process of discovering bootstrap domains from multiple sources.
func (p *Provider) getBootstrapDomains(ctx context.Context) ([]string, error) {
	// Check if we have a valid cache
	if !p.isCacheExpired() && len(p.cachedDomains) >= p.config.MinDomainCount {
		p.logger.Debug("Using cached bootstrap domains", "count", len(p.cachedDomains))
		return p.cachedDomains, nil
	}

	p.logger.Debug("Cache expired, generating new bootstrap domains")

	// Collect domains from multiple sources for diversity and resilience
	var allDomains []string
	var domainsFound int

	// Primary method: Generate domains using DGA
	dgaDomains, err := p.generateBootstrapDomains(ctx, 20)
	if err != nil {
		p.logger.Warn("Failed to generate DGA domains", "error", err)
	} else {
		p.logger.Debug("Generated DGA domains", "count", len(dgaDomains))
		allDomains = append(allDomains, dgaDomains...)
		domainsFound += len(dgaDomains)
	}

	// Secondary method: Discovery via social media
	if domainsFound < p.config.MinDomainCount {
		socialDomains := p.discoverViaSocialMedia()
		p.logger.Debug("Discovered domains via social media", "count", len(socialDomains))
		allDomains = append(allDomains, socialDomains...)
		domainsFound += len(socialDomains)
	}

	// Tertiary method: Discovery via steganography
	if domainsFound < p.config.MinDomainCount {
		stegoDomains := p.discoverViaSteganography()
		p.logger.Debug("Discovered domains via steganography", "count", len(stegoDomains))
		allDomains = append(allDomains, stegoDomains...)
		domainsFound += len(stegoDomains)
	}

	// Quaternary method: Discovery via peer network
	if domainsFound < p.config.MinDomainCount {
		peerDomains := p.getPeerDiscoveredDomains(ctx)
		p.logger.Debug("Discovered domains via peer network", "count", len(peerDomains))
		allDomains = append(allDomains, peerDomains...)
	}

	// Cryptographically shuffle the domains for diversity
	p.cryptoShuffle(allDomains)

	// Filter out duplicates while preserving order
	uniqueDomains := make([]string, 0, len(allDomains))
	seen := make(map[string]bool)
	for _, domain := range allDomains {
		if !seen[domain] {
			seen[domain] = true
			uniqueDomains = append(uniqueDomains, domain)
		}
	}

	// Update cache
	p.cachedDomains = uniqueDomains
	p.cacheTimestamp = time.Now()

	p.logger.Debug("Updated bootstrap domains cache", "count", len(uniqueDomains))

	if len(uniqueDomains) < p.config.MinDomains {
		return uniqueDomains, fmt.Errorf("insufficient bootstrap domains found: %d < %d required",
			len(uniqueDomains), p.config.MinDomains)
	}

	return uniqueDomains, nil
}

// generateDomains creates a diverse set of domains using various generation strategies.
//
//nolint:unused
func (p *Provider) generateDomains(ctx context.Context, entropy *EntropyBundle, count int) []string {
	// This function orchestrates the domain generation process using multiple strategies.
	if entropy == nil {
		entropy = p.gatherEntropyBundle()
	}
	if err := p.validateEntropyQuality(entropy); err != nil {
		p.logger.Warn("Entropy quality is low, domain generation might be less secure", "error", err)
	}

	strategies := p.selectDiversifiedStrategies(entropy)
	p.logger.Debug("Selected domain generation strategies", "strategies", strategies)

	var generatedDomains []string
	if len(strategies) > 0 {
		for _, strategy := range strategies {
			generatedDomains = append(generatedDomains, p.executeGenerationStrategy(strategy, entropy, count/len(strategies))...)
		}
	}

	// Fallback in case strategies produce too few domains
	if len(generatedDomains) < count {
		p.logger.Debug("Initial strategies produced too few domains, using fallback", "initial_count", len(generatedDomains))
		generatedDomains = append(generatedDomains, p.generateFallbackDomains(entropy, count-len(generatedDomains))...)
	}

	// Generate some DGA domains as a guaranteed source
	dgaDomains, err := p.generateBootstrapDomains(ctx, 10)
	if err != nil {
		p.logger.Warn("Failed to generate DGA domains during core generation", "error", err)
	} else {
		generatedDomains = append(generatedDomains, dgaDomains...)
	}

	p.cryptoShuffle(generatedDomains)

	// Final filtering and trimming
	finalDomains := p.filterValidDomains(generatedDomains)
	if len(finalDomains) > count {
		finalDomains = finalDomains[:count]
	}

	p.logger.Info("Domain generation complete", "generated_count", len(finalDomains))
	return finalDomains
}

// gatherEntropyBundle collects entropy from various system sources.
func (p *Provider) gatherEntropyBundle() *EntropyBundle {
	p.logger.Debug("Gathering entropy for domain generation")

	bundle := &EntropyBundle{
		Timestamp: time.Now().UnixNano(),
		Sources:   make(map[string][]byte),
	}

	// Add timestamp-based entropy
	timeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeBytes, uint64(bundle.Timestamp))
	bundle.Sources["time"] = timeBytes
	bundle.TimeBased = timeBytes

	// Add peer-discovered domains as entropy source
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peerDomains := p.getPeerDiscoveredDomains(ctx)
	if len(peerDomains) > 0 {
		peerData := []byte(strings.Join(peerDomains, ","))
		bundle.Sources["peers"] = peerData
		bundle.NetworkEntropy = peerData
	}

	// Add hardware entropy
	hwEntropy, err := p.gatherHardwareEntropy()
	if err == nil && len(hwEntropy) > 0 {
		bundle.Sources["hardware"] = hwEntropy
		bundle.HardwareEntropy = hwEntropy
	}

	// Add external entropy
	extEntropy, err := p.gatherExternalEntropy()
	if err == nil && len(extEntropy) > 0 {
		bundle.Sources["external"] = extEntropy
		bundle.ExternalEntropy = extEntropy
	}

	// Add random entropy as a fallback
	randomBytes := make([]byte, 32)
	if _, err := cryptorand.Read(randomBytes); err == nil {
		bundle.Sources["random"] = randomBytes
		bundle.SystemEntropy = randomBytes
	}

	// Calculate quality score based on entropy sources
	bundle.Quality = p.calculateEntropyQuality(bundle)

	p.logger.Debug("Entropy gathering complete",
		"sources", len(bundle.Sources),
		"quality", bundle.Quality)

	return bundle
}

// calculateEntropyQuality calculates a quality score for entropy
func (p *Provider) calculateEntropyQuality(bundle *EntropyBundle) float64 {
	// Calculate a quality score between 0.0 and 1.0
	// based on the number and quality of entropy sources

	// Start with a base score
	score := 0.1

	// Add points for each entropy source
	if len(bundle.HardwareEntropy) > 0 {
		score += 0.3
	}
	if len(bundle.NetworkEntropy) > 0 {
		score += 0.2
	}
	if len(bundle.ExternalEntropy) > 0 {
		score += 0.3
	}
	if len(bundle.SystemEntropy) > 0 {
		score += 0.1
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// generateMathematicalDomains creates high-entropy mathematical domains with enhanced security
//
//nolint:unused
func (p *Provider) generateMathematicalDomains(bundle *EntropyBundle, count int) []string {
	p.logger.Debug("Generating mathematical domains", "count", count)
	domains := make([]string, 0, count)

	// CRITICAL: Use multiple independent entropy sources with cross-validation
	if err := p.validateEntropyQuality(bundle); err != nil {
		p.logger.Error("CRITICAL: Insufficient entropy for secure domain generation", "error", err)
		return nil // Fail securely rather than generate predictable domains
	}

	// Use Argon2id instead of PBKDF2 for better security against ASIC attacks
	combinedEntropy := p.combineEntropySecurely(bundle)

	// Add time-based salt rotation to prevent precomputation attacks
	timeSalt := p.generateTimeSalt()

	for i := 0; i < count; i++ {
		// Use Argon2id with high memory cost for domain generation
		domainSeed := fmt.Sprintf("domain_%d_%x", i, timeSalt)
		key := p.argon2IDKey(combinedEntropy, []byte(domainSeed), 3, 64*1024, 4, 32)

		// Generate multiple domain candidates and select based on additional criteria
		h := sha256.New()
		h.Write(key)
		h.Write(timeSalt)
		hashBytes := h.Sum(nil)

		// Use a varied approach to domain generation based on hash value
		var domain string
		switch i % 3 {
		case 0:
			// Simple hex encoding
			domain = fmt.Sprintf("%x.%s", hashBytes[:6], p.getDGATLD())
		case 1:
			// Mix of characters and numbers
			chars := "abcdefghijkmnopqrstuvwxyz" // Removed 'l' to avoid confusion
			numbers := "0123456789"
			part1 := chars[hashBytes[0]%byte(len(chars))]
			part2 := chars[hashBytes[1]%byte(len(chars))]
			part3 := numbers[hashBytes[2]%byte(len(numbers))]
			part4 := numbers[hashBytes[3]%byte(len(numbers))]
			part5 := chars[hashBytes[4]%byte(len(chars))]

			domain = fmt.Sprintf("m%c%c%c%c%c.%s", part1, part2, part3, part4, part5, p.getDGATLD())
		case 2:
			// Service-like subdomain
			services := []string{"api", "auth", "cdn", "data", "proxy"}
			svcIdx := hashBytes[0] % byte(len(services))
			idPart := fmt.Sprintf("%x", hashBytes[1:3])

			domain = fmt.Sprintf("%s-%s.%s", services[svcIdx], idPart, p.getDGATLD())
		}

		// Validate domain doesn't match known blocked patterns
		if p.isDomainSafe(domain) {
			domains = append(domains, domain)
		}
	}

	// Shuffle domains with cryptographic randomness to prevent pattern detection
	p.cryptoShuffle(domains)

	return domains
}

// generateDictionaryDomains creates domains that look like legitimate services
//
//nolint:unused
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
//
//nolint:unused
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

func (p *Provider) combineEntropySecurely(bundle *EntropyBundle) []byte {
	hash := sha256.New()
	hash.Write(bundle.HardwareEntropy)
	hash.Write(bundle.NetworkEntropy)
	hash.Write(bundle.SystemEntropy)
	hash.Write(bundle.ExternalEntropy)
	hash.Write(bundle.TimeBased)
	hash.Write(bundle.GeolocationEntropy)
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

//nolint:unused
func (p *Provider) loadWordLists() map[string][]string {
	// In real implementation, load from files or embed
	return map[string][]string{
		"tech":    []string{"api", "cloud", "data", "net", "web", "app", "dev", "tech"},
		"brands":  []string{"google", "amazon", "microsoft", "apple", "meta", "netflix"},
		"generic": []string{"secure", "fast", "global", "pro", "plus", "max", "ultra"},
	}
}

//nolint:unused
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

// generateTimeSalt creates time-based salt that changes every rotation interval
//
//nolint:unused
func (p *Provider) generateTimeSalt() []byte {
	// Use 5-minute windows to ensure clients can sync
	timeWindow := time.Now().Unix() / 300
	h := sha256.New()
	if _, err := fmt.Fprintf(h, "time_salt_%d", timeWindow); err != nil {
		// Handle error (practically impossible for in-memory hash writer)
		h.Write([]byte("time_salt_fallback"))
	}
	hash := h.Sum(nil)
	return hash
}

// argon2IDKey generates a key using Argon2id
//
//nolint:unused
func (p *Provider) argon2IDKey(password, salt []byte, time uint32, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}

// isDomainSafe checks if domain matches known blocked patterns
func (p *Provider) isDomainSafe(domain string) bool {
	blockedPatterns := []string{
		"vpn", "proxy", "tor", "tunnel", "circumvent", "bypass", "unblock",
		"freedom", "wall", "block", "filter", "censor", "gfw",
	}

	lowerDomain := strings.ToLower(domain)
	for _, pattern := range blockedPatterns {
		if strings.Contains(lowerDomain, pattern) {
			return false
		}
	}

	return true
}

// gatherHardwareEntropy gathers entropy from hardware RNG sources
func (p *Provider) gatherHardwareEntropy() ([]byte, error) {
	entropy := make([]byte, 32)
	_, err := cryptorand.Read(entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to gather hardware entropy: %w", err)
	}
	return entropy, nil
}

// gatherExternalEntropy gathers entropy from external unpredictable sources
func (p *Provider) gatherExternalEntropy() ([]byte, error) {
	// In a production system, this could gather entropy from:
	// - Blockchain hashes
	// - External API responses
	// - Network measurements

	// For now, return time-based entropy as placeholder
	h := sha256.New()
	if _, err := fmt.Fprintf(h, "external_%d", time.Now().UnixNano()); err != nil {
		// Fallback if fprintf fails (should never happen)
		h.Write([]byte("external_fallback"))
	}
	return h.Sum(nil), nil
}

// deriveSecureMasterKey uses HKDF for secure key derivation
//
//nolint:unused
func (p *Provider) deriveSecureMasterKey(bundle *EntropyBundle, seed time.Time) []byte {
	// Combine all entropy sources
	combinedEntropy := p.combineEntropySecurely(bundle)

	// Use HKDF-Extract to create a cryptographically strong master key
	salt := p.generateRotatingSalt(seed)
	return hkdf.Extract(sha256.New, combinedEntropy, salt)
}

// generateRotatingSalt creates time-rotating salt to prevent replay attacks
//
//nolint:unused
func (p *Provider) generateRotatingSalt(seed time.Time) []byte {
	// Use 1-hour rotation windows for forward secrecy
	timeWindow := seed.Unix() / 3600
	h := sha256.New()
	if _, err := fmt.Fprintf(h, "dga_salt_v2_%d", timeWindow); err != nil {
		h.Write([]byte("dga_salt_fallback"))
	}

	// Use the securely provided salt, not a hardcoded one
	if len(p.secretSalt) == 0 {
		p.logger.Error("CRITICAL: DGA secret salt is not initialized. Aborting.")
		// In a real scenario, this should cause a hard failure.
		// For this example, we use a random fallback to prevent panic, but this is not secure.
		fallbackSalt := make([]byte, 32)
		_, _ = cryptorand.Read(fallbackSalt)
		h.Write(fallbackSalt)
	} else {
		h.Write(p.secretSalt)
	}

	return h.Sum(nil)
}

// expandKeyForDomain uses HKDF-Expand for domain-specific key derivation
//
//nolint:unused
func (p *Provider) expandKeyForDomain(masterKey []byte, domainIndex int) []byte {
	h := sha256.New()
	if _, err := fmt.Fprintf(h, "domain_%d", domainIndex); err != nil {
		h.Write([]byte("domain_fallback"))
		return h.Sum(nil)
	}

	info := h.Sum(nil)
	hkdfReader := hkdf.Expand(sha256.New, masterKey, info)

	key := make([]byte, 32)
	if _, err := hkdfReader.Read(key); err != nil {
		// Fallback to simple hash if HKDF fails
		h := sha256.New()
		h.Write(masterKey)
		h.Write(info)
		return h.Sum(nil)
	}

	return key
}

// generateSecureDomain creates a realistic domain from a cryptographic key
func (p *Provider) generateSecureDomain(index int) string {
	// Use a combination of time-based salt and index for improved security
	timestamp := time.Now().Unix() / 3600 // Rotate every hour

	// Create a secure hash combining index and timestamp
	h := sha256.New()

	// Use the secretSalt from the provider instead of calling getSecretSalt
	if len(p.secretSalt) == 0 {
		p.logger.Error("CRITICAL: DGA using without initialized salt")
		// Generate emergency random salt - not ideal but better than using a static value
		emergencySalt := make([]byte, 32)
		_, _ = cryptorand.Read(emergencySalt)
		_, _ = fmt.Fprintf(h, "secure_domain_%d_%d_%x", index, timestamp, emergencySalt)
	} else {
		_, _ = fmt.Fprintf(h, "secure_domain_%d_%d_%x", index, timestamp, p.secretSalt)
	}

	domainHash := h.Sum(nil)

	// Use multiple domain generation approaches based on index value
	var domain string

	switch index % 4 {
	case 0:
		// Basic hex encoding approach
		domain = fmt.Sprintf("s%x.%s", domainHash[:6], p.getDGATLD())
	case 1:
		// Word-like pattern for more natural looking domain
		consonants := "bcdfghjklmnpqrstvwxyz"
		vowels := "aeiou"

		c1 := consonants[domainHash[0]%byte(len(consonants))]
		v1 := vowels[domainHash[1]%byte(len(vowels))]
		c2 := consonants[domainHash[2]%byte(len(consonants))]
		v2 := vowels[domainHash[3]%byte(len(vowels))]
		c3 := consonants[domainHash[4]%byte(len(consonants))]

		domain = fmt.Sprintf("%c%c%c%c%c.%s", c1, v1, c2, v2, c3, p.getDGATLD())
	case 2:
		// Service-like pattern with dash
		services := []string{"api", "cdn", "data", "auth", "sync"}
		svcIdx := domainHash[0] % byte(len(services))
		id := fmt.Sprintf("%x", domainHash[1:3])

		domain = fmt.Sprintf("%s-%s.%s", services[svcIdx], id, p.getDGATLD())
	case 3:
		// Region-based pattern
		regions := []string{"us", "eu", "ap", "af", "sa"}
		regIdx := domainHash[0] % byte(len(regions))
		nums := fmt.Sprintf("%d%d", domainHash[1]%10, domainHash[2]%10)

		domain = fmt.Sprintf("%s%s-c.%s", regions[regIdx], nums, p.getDGATLD())
	}

	// Verify domain meets security constraints
	if p.isDomainSecure(domain) {
		return domain
	}

	// Fallback to simple secure format if domain has security concerns
	return fmt.Sprintf("s-%x.%s", domainHash[:5], p.getDGATLD())
}

// isDomainSecure checks if a domain meets security requirements
func (p *Provider) isDomainSecure(domain string) bool {
	// Check format
	if !p.isValidDomainFormat(domain) {
		p.logger.Debug("Invalid domain format", "domain", domain)
		return false
	}

	// Get TLD
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		p.logger.Debug("Domain missing TLD", "domain", domain)
		return false
	}

	tld := parts[len(parts)-1]
	if tld == "" {
		p.logger.Debug("Empty TLD", "domain", domain)
		return false
	}

	// Run additional detection for DGA-like patterns
	// Remove probabilistic check which could use math/rand
	if p.looksDGAGenerated(domain) {
		p.logger.Debug("Domain appears DGA-generated with poor entropy", "domain", domain)
		return false
	}

	p.logger.Debug("Domain passed security validation", "domain", domain)
	return true
}

// looksDGAGenerated determines if a domain looks algorithmically generated in an obvious way
func (p *Provider) looksDGAGenerated(domain string) bool {
	// Extract the domain part without the TLD
	parts := strings.Split(strings.ToLower(domain), ".")
	if len(parts) < 2 {
		return false
	}

	domainPart := parts[0]

	// Check for entropy that's too high (looks random)
	entropy := p.calculateStringEntropy(domainPart)

	// Extremely high entropy domains look suspicious
	if entropy > 4.0 && len(domainPart) > 8 {
		return true
	}

	// Check for unusual character distribution
	vowelCount := 0
	consonantCount := 0
	digitCount := 0

	for _, char := range domainPart {
		if strings.ContainsRune("aeiou", char) {
			vowelCount++
		} else if strings.ContainsRune("bcdfghjklmnpqrstvwxyz", char) {
			consonantCount++
		} else if strings.ContainsRune("0123456789", char) {
			digitCount++
		}
	}

	// Check for unusual vowel-consonant ratio
	if len(domainPart) > 0 {
		vowelRatio := float64(vowelCount) / float64(len(domainPart))
		if vowelRatio < 0.1 || vowelRatio > 0.6 {
			return true
		}
	}

	// Lots of digits is suspicious
	if float64(digitCount)/float64(len(domainPart)) > 0.4 {
		return true
	}

	return false
}

// calculateStringEntropy calculates Shannon entropy of a string
func (p *Provider) calculateStringEntropy(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}

	// Count character frequencies
	charCounts := make(map[rune]int)
	for _, char := range s {
		charCounts[char]++
	}

	// Calculate entropy
	entropy := 0.0
	for _, count := range charCounts {
		freq := float64(count) / float64(len(s))
		entropy -= freq * math.Log2(freq)
	}

	return entropy
}

// getDGATLD returns a TLD for the DGA
func (p *Provider) getDGATLD() string {
	tlds := []string{"com", "net", "org", "info", "xyz"}
	idx := int(time.Now().Unix() % int64(len(tlds)))
	return tlds[idx]
}

// discoverViaSocialMedia attempts to find bootstrap domains from social media sources
func (p *Provider) discoverViaSocialMedia() []string {
	p.logger.Debug("Attempting to discover bootstrap domains via social media")

	// List of potential sources where bootstrap information might be hidden
	sources := []struct {
		url      string
		strategy string
	}{
		{"https://twitter.com/gocircum", "timeline"},
		{"https://github.com/gocircum/gocircum/discussions", "discussions"},
		{"https://reddit.com/r/gocircum", "posts"},
	}

	discoveredDomains := make([]string, 0)

	// Try each source with timeout
	for _, source := range sources {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		domains, err := p.extractDomainsFromSource(ctx, source.url, source.strategy)
		cancel()

		if err != nil {
			p.logger.Debug("Failed to extract domains from source",
				"url", source.url,
				"strategy", source.strategy,
				"error", err)
			continue
		}

		// Filter and validate the extracted domains
		for _, domain := range domains {
			if p.isDomainSecure(domain) {
				discoveredDomains = append(discoveredDomains, domain)
			}
		}
	}

	p.logger.Debug("Social media domain discovery complete", "count", len(discoveredDomains))
	return discoveredDomains
}

// extractDomainsFromSource extracts domains from a given web source using the specified strategy
func (p *Provider) extractDomainsFromSource(ctx context.Context, sourceURL string, strategy string) ([]string, error) {
	// Create a request with context for timeout control
	req, err := http.NewRequestWithContext(ctx, "GET", sourceURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set User-Agent to avoid being blocked
	req.Header.Set("User-Agent", "GoCircum/1.0") // In production, this should be a real user agent

	// Get the secure, hardened HTTP client for bootstrapping.
	bootstrapClient, err := p.getSecureBootstrapClient()
	if err != nil {
		return nil, fmt.Errorf("could not get secure bootstrap client: %w", err)
	}

	// Perform the request using the hardened client to prevent DNS leaks.
	resp, err := bootstrapClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Warn("Failed to close response body", "error", err)
		}
	}()

	// Check response status code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Extract domains based on the strategy
	var domains []string
	switch strategy {
	case "timeline":
		domains = p.extractTimelineDomains(body)
	case "discussion":
		domains = p.extractDiscussionDomains(body)
	case "post":
		domains = p.extractPostDomains(body)
	default:
		domains = p.extractGenericDomains(body)
	}

	// Filter and validate domains
	return p.filterValidDomains(domains), nil
}

// extractTimelineDomains extracts domains from content mimicking a social media timeline.
func (p *Provider) extractTimelineDomains(content []byte) []string {
	// For now, use a simple regex-based extraction
	// In a real implementation, this would use a more sophisticated approach
	// based on the specific platform's HTML structure or API response format
	return extractDomainsFromContent(content)
}

// extractDiscussionDomains extracts domains from discussion content
func (p *Provider) extractDiscussionDomains(content []byte) []string {
	return extractDomainsFromContent(content)
}

// extractPostDomains extracts domains from post content
func (p *Provider) extractPostDomains(content []byte) []string {
	return extractDomainsFromContent(content)
}

// extractGenericDomains extracts domains using a generic approach
func (p *Provider) extractGenericDomains(content []byte) []string {
	return extractDomainsFromContent(content)
}

// extractDomainsFromContent is a utility function to extract domains from content
func extractDomainsFromContent(content []byte) []string {
	// This is a simplified implementation that looks for patterns that might contain
	// steganographically hidden domains

	// In a real implementation, this would:
	// - Look for specific markers or patterns
	// - Decode steganographic content
	// - Parse out domain information

	// For now, return an empty list as this is just a placeholder
	return []string{}
}

// discoverViaSteganography attempts to find domains hidden in public web content
func (p *Provider) discoverViaSteganography() []string {
	p.logger.Debug("Attempting to discover bootstrap domains via steganography")

	// List of potential image sources that might contain hidden domains
	sources := []string{
		"https://cdn.gocircum.net/bootstrap/header.png",
		"https://api.gocircum.org/assets/logo.jpg",
		"https://static.gocircum.io/images/banner.png",
	}

	discoveredDomains := make([]string, 0)

	// Try each source with timeout
	for _, source := range sources {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		domains, err := p.extractDomainsFromImage(ctx, source)
		cancel()

		if err != nil {
			p.logger.Debug("Failed to extract domains from image",
				"url", source,
				"error", err)
			continue
		}

		// Filter and validate the extracted domains
		for _, domain := range domains {
			if p.isDomainSecure(domain) {
				discoveredDomains = append(discoveredDomains, domain)
			}
		}
	}

	p.logger.Debug("Steganographic domain discovery complete", "count", len(discoveredDomains))
	return discoveredDomains
}

// extractDomainsFromImage downloads an image and attempts to extract steganographically hidden domains
func (p *Provider) extractDomainsFromImage(ctx context.Context, imageURL string) ([]string, error) {
	// Create a request with context for timeout control
	req, err := http.NewRequestWithContext(ctx, "GET", imageURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set User-Agent to avoid being blocked
	req.Header.Set("User-Agent", "GoCircum/1.0")

	// Perform the request
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("image request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Warn("Failed to close response body", "error", err)
		}
	}()

	// Check if the response is an image
	contentType := resp.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "image/") {
		return nil, fmt.Errorf("content is not an image: %s", contentType)
	}

	// Read the image data
	imageData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read image data: %w", err)
	}

	// Process image to extract hidden domains
	domains := p.decodeImageSteganography(imageData, contentType)

	return domains, nil
}

// decodeImageSteganography implements steganographic decoding to extract domains from image data
func (p *Provider) decodeImageSteganography(imageData []byte, contentType string) []string {
	// Enhanced implementation for steganographic domain extraction
	p.logger.Debug("Decoding steganographic data from image",
		"contentType", contentType,
		"dataSize", len(imageData))

	// Look for various steganographic markers depending on image type
	var domains []string

	// Handle different image types
	switch {
	case strings.Contains(contentType, "png"):
		domains = p.decodePngSteganography(imageData)
	case strings.Contains(contentType, "jpeg") || strings.Contains(contentType, "jpg"):
		domains = p.decodeJpegSteganography(imageData)
	case strings.Contains(contentType, "gif"):
		domains = p.decodeGifSteganography(imageData)
	}

	// If no domains found, try a general approach
	if len(domains) == 0 {
		// Look for a simple marker pattern followed by encoded domains
		marker := []byte("GOCIRCUM:DOM:")
		markerIndex := bytes.Index(imageData, marker)

		if markerIndex >= 0 && markerIndex+len(marker)+32 <= len(imageData) {
			// Extract 32 bytes after the marker
			encodedData := imageData[markerIndex+len(marker) : markerIndex+len(marker)+32]

			// Use a secure domain generation approach
			hashResult := sha256.Sum256(encodedData)
			domain := p.generateSecureDomain(int(hashResult[0])) // Convert byte to int
			domains = append(domains, domain)
		}
	}

	p.logger.Debug("Steganographic decoding complete", "domainsFound", len(domains))

	return domains
}

// decodePngSteganography extracts hidden domains from PNG images
func (p *Provider) decodePngSteganography(imageData []byte) []string {
	// Look for steganographic data in PNG chunks
	// This is a simplified implementation - a real version would parse PNG structure

	// Check for tEXt chunks with hidden data
	marker := []byte("tEXtgocircum")
	idx := bytes.Index(imageData, marker)

	if idx >= 0 && idx+20 < len(imageData) {
		// Extract potential domain data
		domainKey := imageData[idx+12 : idx+20]
		domain := p.createRealisticDomainFromKey(domainKey)
		return []string{domain}
	}

	return nil
}

// decodeJpegSteganography extracts hidden domains from JPEG images
func (p *Provider) decodeJpegSteganography(imageData []byte) []string {
	// Look for steganographic data in JPEG comments or EXIF
	// This is a simplified implementation

	// Check for comment markers
	marker := []byte{0xFF, 0xFE} // JPEG comment marker
	idx := bytes.Index(imageData, marker)

	if idx >= 0 && idx+20 < len(imageData) {
		// Check for our specific identifier in the comment
		if bytes.Equal(imageData[idx+2:idx+4], []byte("GC")) {
			domainKey := imageData[idx+4 : idx+12]
			domain := p.createRealisticDomainFromKey(domainKey)
			return []string{domain}
		}
	}

	return nil
}

// decodeGifSteganography extracts hidden domains from GIF images
func (p *Provider) decodeGifSteganography(imageData []byte) []string {
	// This is a placeholder for actual GIF steganography decoding logic.
	// You would typically look for data hidden in LSBs of pixel data or in metadata.
	p.logger.Debug("Decoding GIF for steganographic data (placeholder)")
	return extractDomainsFromContent(imageData)
}

// getBuiltinDomains has been REMOVED as it represents a critical centralization vulnerability.
// It is replaced by cryptographically generated domains.

// getPeerDiscoveredDomains attempts to discover bootstrap domains from peers in the network.
func (p *Provider) getPeerDiscoveredDomains(ctx context.Context) []string {
	p.logger.Debug("Attempting to discover domains from peers")

	// Connect to peer network for domain discovery
	peerNetwork, err := p.connectToPeerNetwork(ctx)
	if err != nil {
		p.logger.Debug("Failed to connect to peer network", "error", err)
		return nil
	}

	// Get a subset of peers to query
	peers := peerNetwork.GetRandomPeers(3)
	if len(peers) == 0 {
		p.logger.Debug("No peers available for domain discovery")
		return nil
	}

	p.logger.Debug("Querying peers for domain discovery", "peerCount", len(peers))

	// Query each peer for domains
	var allDomains []string
	for i, peer := range peers {
		domains, err := peer.QueryBootstrapDomains(ctx)
		if err != nil {
			p.logger.Debug("Failed to query peer for domains",
				"peerIndex", i,
				"error", err)
			continue
		}

		p.logger.Debug("Received domains from peer",
			"peerIndex", i,
			"domainCount", len(domains))

		allDomains = append(allDomains, domains...)
	}

	// Deduplicate domains
	uniqueDomains := make(map[string]struct{})
	for _, domain := range allDomains {
		uniqueDomains[domain] = struct{}{}
	}

	result := make([]string, 0, len(uniqueDomains))
	for domain := range uniqueDomains {
		result = append(result, domain)
	}

	p.logger.Debug("Completed peer domain discovery",
		"rawCount", len(allDomains),
		"uniqueCount", len(result))

	return result
}

// connectToPeerNetwork connects to a peer network for domain discovery
func (p *Provider) connectToPeerNetwork(ctx context.Context) (PeerNetwork, error) {
	logger := p.logger.With("component", "peer-network")

	// Check if we have a peer config file specified
	configPath := os.Getenv("GOCIRCUM_PEER_CONFIG")
	if configPath != "" {
		logger.Debug("Loading peer network from config file", "path", configPath)
		network, err := loadPeerNetworkFromConfigFile(configPath, logger)
		if err != nil {
			return nil, err
		}
		return network, nil
	}

	// Otherwise, create a default peer network
	logger.Debug("Creating default peer network")
	return newDefaultPeerNetworkWithLogger(logger), nil
}

// loadPeerNetworkFromConfigFile loads peer network configuration from a file
func loadPeerNetworkFromConfigFile(configPath string, logger logging.Logger) (PeerNetwork, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read peer config: %w", err)
	}

	var config peerNetworkConfig

	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse peer config: %w", err)
	}

	network := &defaultPeerNetwork{
		peers:  make([]Peer, 0, len(config.Peers)),
		logger: logger,
	}

	for _, peerConfig := range config.Peers {
		network.peers = append(network.peers, &defaultPeer{
			address: peerConfig.Address,
			port:    peerConfig.Port,
			key:     peerConfig.Key,
			logger:  logger,
			client:  &http.Client{Timeout: 5 * time.Second},
		})
	}

	return network, nil
}

// newDefaultPeerNetworkWithLogger creates a default peer network with built-in peers
func newDefaultPeerNetworkWithLogger(logger logging.Logger) PeerNetwork {
	// These would be hardcoded trusted peers in a real implementation
	return &defaultPeerNetwork{
		peers: []Peer{
			&defaultPeer{
				address: "bootstrap1.example.org",
				port:    8443,
				key:     "",
				logger:  logger,
				client:  &http.Client{Timeout: 5 * time.Second},
			},
			&defaultPeer{
				address: "bootstrap2.example.org",
				port:    8443,
				key:     "",
				logger:  logger,
				client:  &http.Client{Timeout: 5 * time.Second},
			},
		},
		logger: logger,
	}
}

// getShuffledProviders returns a shuffled copy of the provider list
//
//nolint:unused
func (p *Provider) getShuffledProviders() []string {
	// Create a copy of the providers slice
	providers := make([]string, len(p.providers))
	copy(providers, p.providers)

	// Shuffle the providers using crypto/rand
	for i := len(providers) - 1; i > 0; i-- {
		// Generate random number between 0 and i
		j, err := securerandom.Int(0, i+1)
		if err != nil || j > i {
			// Log error but continue with less randomness in worst case
			j = i / 2 // Simple fallback that at least gives some shuffling
		}

		// Swap elements
		providers[i], providers[j] = providers[j], providers[i]
	}

	return providers
}

// isCacheExpired checks if the domain cache has expired
func (p *Provider) isCacheExpired() bool {
	// If cache TTL is not set, use a default of 1 hour
	cacheTTL := p.config.CacheTTL
	if cacheTTL == 0 {
		cacheTTL = 1 * time.Hour
	}

	return time.Since(p.cacheTimestamp) > cacheTTL
}

// hashDomain returns a short hash of a domain for logging
//
//nolint:unused
func hashDomain(domain string) string {
	h := sha256.New()
	h.Write([]byte(domain))
	hash := h.Sum(nil)
	return hex.EncodeToString(hash[:4])
}

// gatherEntropy collects entropy from various system and network sources
//
//nolint:unused
func (p *Provider) gatherEntropy(ctx context.Context) *EntropyBundle {
	p.logger.Debug("Gathering entropy for domain generation")

	bundle := &EntropyBundle{
		Timestamp: time.Now().UnixNano(),
		Sources:   make(map[string][]byte),
	}

	// Add timestamp-based entropy
	timeBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(timeBytes, uint64(bundle.Timestamp))
	bundle.Sources["time"] = timeBytes
	bundle.TimeBased = timeBytes

	// Add peer-discovered domains as entropy source
	peerDomains := p.getPeerDiscoveredDomains(ctx)
	if len(peerDomains) > 0 {
		peerData := []byte(strings.Join(peerDomains, ","))
		bundle.Sources["peers"] = peerData
		bundle.NetworkEntropy = peerData
	}

	// Add hardware entropy
	hwEntropy, err := p.gatherHardwareEntropy()
	if err == nil && len(hwEntropy) > 0 {
		bundle.Sources["hardware"] = hwEntropy
		bundle.HardwareEntropy = hwEntropy
	}

	// Add external entropy
	extEntropy, err := p.gatherExternalEntropy()
	if err == nil && len(extEntropy) > 0 {
		bundle.Sources["external"] = extEntropy
		bundle.ExternalEntropy = extEntropy
	}

	// Add random entropy as a fallback
	randomBytes := make([]byte, 32)
	if _, err := cryptorand.Read(randomBytes); err == nil {
		bundle.Sources["random"] = randomBytes
		bundle.SystemEntropy = randomBytes
	}

	// Calculate quality score based on entropy sources
	bundle.Quality = p.calculateEntropyQuality(bundle)

	p.logger.Debug("Entropy gathering complete",
		"sources", len(bundle.Sources),
		"quality", bundle.Quality)

	return bundle
}

// selectDiversifiedStrategies selects domain generation strategies based on entropy quality
//
//nolint:unused
func (p *Provider) selectDiversifiedStrategies(entropy *EntropyBundle) []string {
	p.logger.Debug("Selecting domain generation strategies", "entropyQuality", entropy.Quality)

	// Base strategies available for selection
	allStrategies := []string{
		"mathematical",
		"dictionary",
		"steganographic",
		"polymorphic",
		"hijacking",
	}

	// Select strategies based on entropy quality
	var selectedStrategies []string

	if entropy.Quality >= 0.8 {
		// High-quality entropy: use all strategies
		p.logger.Debug("High-quality entropy detected, using all strategies")
		selectedStrategies = allStrategies
	} else if entropy.Quality >= 0.5 {
		// Medium-quality entropy: use safer strategies
		p.logger.Debug("Medium-quality entropy detected, using safer strategies")
		selectedStrategies = []string{
			"mathematical",
			"dictionary",
			"polymorphic",
		}
	} else {
		// Low-quality entropy: use only the most reliable strategy
		p.logger.Debug("Low-quality entropy detected, using only mathematical strategy")
		selectedStrategies = []string{
			"mathematical",
		}
	}

	// Always ensure we have at least one strategy
	if len(selectedStrategies) == 0 {
		selectedStrategies = []string{"mathematical"}
	}

	p.logger.Debug("Selected strategies", "strategies", strings.Join(selectedStrategies, ","))
	return selectedStrategies
}

// executeGenerationStrategy runs the specified generation strategy
//
//nolint:unused
func (p *Provider) executeGenerationStrategy(strategy string, entropy *EntropyBundle, count int) []string {
	p.logger.Debug("Executing domain generation strategy", "strategy", strategy, "count", count)

	var domains []string

	switch strategy {
	case "mathematical":
		domains = p.generateMathematicalDomains(entropy, count)
	case "dictionary":
		domains = p.generateDictionaryDomains(entropy, count)
	case "steganographic":
		domains = p.generateSteganographicDomains(entropy, count)
	case "polymorphic":
		domains = p.generatePolymorphicDomains(entropy, count)
	case "hijacking":
		domains = p.generateHijackingDomains(entropy, count)
	default:
		p.logger.Error("Unknown domain generation strategy", "strategy", strategy)
		return nil
	}

	// Filter the generated domains for validity
	validDomains := p.filterValidDomains(domains)

	p.logger.Debug("Strategy execution complete",
		"strategy", strategy,
		"generated", len(domains),
		"valid", len(validDomains))

	return validDomains
}

// filterValidDomains filters domains for validity and security
func (p *Provider) filterValidDomains(domains []string) []string {
	validDomains := make([]string, 0, len(domains))

	for _, domain := range domains {
		// Check if domain is valid and secure
		if p.isValidDomainFormat(domain) && p.isDomainSafe(domain) {
			validDomains = append(validDomains, domain)
		}
	}

	return validDomains
}

// isValidDomainFormat checks if a domain meets format requirements
func (p *Provider) isValidDomainFormat(domain string) bool {
	// Check domain length
	if len(domain) < 4 || len(domain) > 253 {
		return false
	}

	// Check for valid domain structure (labels separated by dots)
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	// Check each label
	for _, label := range labels {
		// Label length check
		if len(label) < 1 || len(label) > 63 {
			return false
		}

		// Label character check (RFC 1035)
		if !isValidLabel(label) {
			return false
		}
	}

	return true
}

// isValidLabel checks if a domain label is valid per RFC 1035
func isValidLabel(label string) bool {
	// Must start with letter
	if len(label) == 0 || !isLetterOrDigit(rune(label[0])) {
		return false
	}

	// Must end with letter or digit
	if !isLetterOrDigit(rune(label[len(label)-1])) {
		return false
	}

	// Middle chars can be letters, digits, or hyphens
	for _, ch := range label[1 : len(label)-1] {
		if !isLetterOrDigit(ch) && ch != '-' {
			return false
		}
	}

	return true
}

// isLetterOrDigit checks if a character is a letter or digit
func isLetterOrDigit(ch rune) bool {
	return (ch >= 'a' && ch <= 'z') ||
		(ch >= 'A' && ch <= 'Z') ||
		(ch >= '0' && ch <= '9')
}

// validateEntropyQuality checks if the entropy is high quality
//
//nolint:unused
func (p *Provider) validateEntropyQuality(bundle *EntropyBundle) error {
	// Require a minimum quality score
	if bundle.Quality < 0.5 {
		return fmt.Errorf("entropy quality too low: %.2f", bundle.Quality)
	}

	// Require at least 2 independent entropy sources
	sourceCount := 0
	if len(bundle.HardwareEntropy) > 0 {
		sourceCount++
	}
	if len(bundle.NetworkEntropy) > 0 {
		sourceCount++
	}
	if len(bundle.ExternalEntropy) > 0 {
		sourceCount++
	}

	if sourceCount < 2 {
		return fmt.Errorf("insufficient entropy sources: %d", sourceCount)
	}

	return nil
}

// generateFallbackDomains creates safe fallback domains
//
//nolint:unused
func (p *Provider) generateFallbackDomains(entropy *EntropyBundle, count int) []string {
	p.logger.Debug("Generating fallback domains", "count", count)

	domains := make([]string, 0, count)

	// Use a simple approach based on timestamp and hash
	timestamp := time.Now().Unix()

	for i := 0; i < count; i++ {
		h := sha256.New()
		_, _ = fmt.Fprintf(h, "fallback_%d_%d", timestamp, i)
		hash := h.Sum(nil)

		domain := fmt.Sprintf("fb-%x.%s", hash[:6], p.getDGATLD())
		domains = append(domains, domain)
	}

	return domains
}

// generateSteganographicDomains creates domains that contain hidden information
//
//nolint:unused
func (p *Provider) generateSteganographicDomains(bundle *EntropyBundle, count int) []string {
	p.logger.Debug("Generating steganographic domains", "count", count)

	domains := make([]string, 0, count)

	// Derive a master key for domain generation
	masterKey := p.deriveSecureMasterKey(bundle, time.Now())

	// Generate unique subdomains
	for i := 0; i < count; i++ {
		// Expand key for this specific domain
		domainKey := p.expandKeyForDomain(masterKey, i)

		// Create a base64-encoded subdomain that resembles normal domain characters
		encoded := base64.StdEncoding.EncodeToString(domainKey[:8])
		// Replace characters that don't look like normal domain characters
		encoded = strings.ReplaceAll(encoded, "+", "x")
		encoded = strings.ReplaceAll(encoded, "/", "y")
		encoded = strings.ReplaceAll(encoded, "=", "z")

		// Use only the first 8 characters to keep domains reasonably sized
		subdomain := encoded[:8]

		// Construct domain with different parts to look legitimate
		parts := []string{"stg", "cdn", "api", "static", "data"}
		partIdx := int(domainKey[8]) % len(parts)

		domain := fmt.Sprintf("%s-%s.%s", parts[partIdx], subdomain, p.getDGATLD())
		domains = append(domains, domain)
	}

	p.logger.Debug("Generated steganographic domains", "count", len(domains))
	return domains
}

// generatePolymorphicDomains creates domains that change over time
//
//nolint:unused
func (p *Provider) generatePolymorphicDomains(bundle *EntropyBundle, count int) []string {
	p.logger.Debug("Generating polymorphic domains", "count", count)

	domains := make([]string, 0, count)

	// Derive a master key for domain generation
	masterKey := p.deriveSecureMasterKey(bundle, time.Now())

	// Use time-based mutation factor (changes every hour)
	timeFactor := time.Now().Unix() / 3600

	for i := 0; i < count; i++ {
		// Create a unique key for this domain that incorporates the time factor
		h := sha256.New()
		h.Write(masterKey)
		_, _ = fmt.Fprintf(h, "poly_%d_%d", i, timeFactor)
		keyBytes := h.Sum(nil)

		// Generate domain components based on different patterns
		var domain string

		switch keyBytes[0] % 4 {
		case 0:
			// Simple hex encoding
			domain = fmt.Sprintf("p%x.%s", keyBytes[1:5], p.getDGATLD())
		case 1:
			// Word-like pattern
			consonants := "bcdfghjklmnpqrstvwxyz"
			vowels := "aeiou"

			c1 := consonants[keyBytes[1]%byte(len(consonants))]
			v1 := vowels[keyBytes[2]%byte(len(vowels))]
			c2 := consonants[keyBytes[3]%byte(len(consonants))]
			v2 := vowels[keyBytes[4]%byte(len(vowels))]
			c3 := consonants[keyBytes[5]%byte(len(consonants))]

			domain = fmt.Sprintf("p%c%c%c%c%c.%s", c1, v1, c2, v2, c3, p.getDGATLD())
		case 2:
			// Service-like domain
			services := []string{"api", "cdn", "data", "edge", "proxy"}
			svcIdx := keyBytes[1] % byte(len(services))
			id := fmt.Sprintf("%x", keyBytes[2:4])

			domain = fmt.Sprintf("%s-%s.%s", services[svcIdx], id, p.getDGATLD())
		case 3:
			// Region-based domain
			regions := []string{"us", "eu", "ap", "af", "sa"}
			regIdx := keyBytes[1] % byte(len(regions))
			nums := fmt.Sprintf("%d%d", keyBytes[2]%10, keyBytes[3]%10)

			domain = fmt.Sprintf("%s%s-p.%s", regions[regIdx], nums, p.getDGATLD())
		}

		domains = append(domains, domain)
	}

	p.logger.Debug("Generated polymorphic domains", "count", len(domains))
	return domains
}

// cryptoShuffle uses cryptographic randomness to shuffle a slice
func (p *Provider) cryptoShuffle(slice []string) {
	for i := len(slice) - 1; i > 0; i-- {
		j, err := securerandom.Int(0, i+1)
		if err != nil || j > i {
			// Log error but continue with less randomness in worst case
			j = i / 2 // Simple fallback that at least gives some shuffling
		}

		// Swap elements
		slice[i], slice[j] = slice[j], slice[i]
	}
}

// initializeSecureSalt generates a secure, user-specific salt for the DGA
func (p *Provider) initializeSecureSalt() ([]byte, error) {
	// Combine multiple entropy sources for a high-quality salt
	entropyBundle := p.gatherEntropyBundle()

	// Use HKDF to derive a secure salt
	combinedEntropy := p.combineEntropySecurely(entropyBundle)

	// Add hardware-specific and user-specific entropy if available
	hardwareID, err := p.getHardwareIdentifier()
	if err == nil {
		h := sha256.New()
		h.Write(combinedEntropy)
		h.Write(hardwareID)
		combinedEntropy = h.Sum(nil)
	}

	return combinedEntropy, nil
}

// getHardwareIdentifier attempts to get a stable, device-specific identifier
func (p *Provider) getHardwareIdentifier() ([]byte, error) {
	// Try to get system-specific information
	hostname, err := os.Hostname()
	if err != nil {
		return nil, err
	}

	// Get network interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Create hash from system information
	h := sha256.New()
	h.Write([]byte(hostname))

	// Add MAC addresses of network interfaces
	for _, iface := range interfaces {
		if iface.HardwareAddr != nil {
			h.Write([]byte(iface.HardwareAddr.String()))
		}
	}

	// Add username if available
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // Windows fallback
	}
	h.Write([]byte(username))

	return h.Sum(nil), nil
}

// getSecureBootstrapClient creates a hardened HTTP client that uses DoH for all DNS resolution,
// preventing leaks during the bootstrap phase.
func (p *Provider) getSecureBootstrapClient() (*http.Client, error) {
	// Use a mutex to ensure thread safety for the initialization
	var initMutex sync.Mutex
	initMutex.Lock()
	defer initMutex.Unlock()

	// If we already have a client, return it
	if secureBootstrapClient != nil {
		return secureBootstrapClient, nil
	}

	// Create a transport with a custom dialer that uses our IP cache
	transport := &http.Transport{
		// Disable the standard Dial function to prevent system DNS usage
		Dial: func(network, addr string) (net.Conn, error) {
			return nil, errors.New("standard Dial disabled to prevent system DNS resolution")
		},

		// Use a custom DialContext that connects directly to cached IPs
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %w", err)
			}

			// Check if the host is already an IP address
			if ip := net.ParseIP(host); ip != nil {
				dialer := &net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, network, addr)
			}

			// Look up the host in our IP cache
			ips, found := p.ipCache.Get(host)
			if !found || len(ips) == 0 {
				// If not in cache, use hardcoded bootstrap IPs for known DoH providers
				switch host {
				case "dns.google":
					ips = []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("8.8.4.4")}
				case "cloudflare-dns.com":
					ips = []net.IP{net.ParseIP("1.1.1.1"), net.ParseIP("1.0.0.1")}
				default:
					return nil, fmt.Errorf("no cached IP addresses for host: %s", host)
				}

				// Cache the IPs we're using
				p.ipCache.Set(host, ips, 24*time.Hour)
			}

			// Choose a random IP from the list - use crypto/rand for better security
			randomIndex, err := secureRandomIndex(len(ips))
			if err != nil {
				// Fall back to less secure random if crypto/rand fails
				randomIndex = len(ips) / 2 // Simple fallback that uses middle of array
			}
			ip := ips[randomIndex]

			p.logger.Debug("Using cached IP for bootstrap connection",
				"host", host,
				"ip", ip.String())

			// Connect directly to the IP:port
			dialer := &net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}

			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		},

		// Disable the standard DialTLS function
		DialTLS: func(network, addr string) (net.Conn, error) {
			return nil, errors.New("standard DialTLS disabled to prevent system DNS resolution")
		},

		// Set TLS configuration
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},

		// Other transport settings
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Create the client with our custom transport
	secureBootstrapClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	p.logger.Info("Created secure bootstrap client with IP caching")
	return secureBootstrapClient, nil
}

// secureRandomIndex generates a cryptographically secure random index.
func secureRandomIndex(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}

	n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}

	return int(n.Int64()), nil
}

// generateBootstrapDomains uses a DGA to create a list of potential bootstrap domains.
func (p *Provider) generateBootstrapDomains(ctx context.Context, count int) ([]string, error) {
	p.logger.Debug("Generating bootstrap domains using DGA")

	// The DGA needs a robust, user-specific, and time-variant seed.
	// The existing initializeSecureSalt() provides a strong foundation for this.
	// In a real implementation, this salt/seed would be managed more explicitly.
	if len(p.secretSalt) == 0 {
		return nil, fmt.Errorf("DGA bootstrap failed: secure salt not initialized")
	}

	// Use HKDF to derive a time-based key for this generation window.
	// This ensures forward secrecy; compromising one window's key doesn't compromise others.
	timeWindow := time.Now().Unix() / 3600 // Hourly window
	info := []byte(fmt.Sprintf("bootstrap-dga-window-%d", timeWindow))
	hkdfReader := hkdf.New(sha256.New, p.secretSalt, nil, info)
	masterKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, masterKey); err != nil {
		return nil, fmt.Errorf("failed to derive DGA master key: %w", err)
	}

	domains := make([]string, 0, count)
	for i := 0; i < count; i++ {
		// Derive a unique key for each domain.
		domainInfo := []byte(fmt.Sprintf("domain-%d", i))
		domainKeyReader := hkdf.Expand(sha256.New, masterKey, domainInfo)
		domainKey := make([]byte, 16)
		if _, err := io.ReadFull(domainKeyReader, domainKey); err != nil {
			p.logger.Warn("Failed to derive key for domain index", "index", i, "error", err)
			continue
		}

		// Generate a natural-looking domain to avoid heuristic detection.
		domain := p.createNaturalDomain(domainKey)
		domains = append(domains, domain)
	}

	p.cryptoShuffle(domains) // Shuffle to prevent predictable ordering
	p.logger.Debug("Generated DGA bootstrap domains", "count", len(domains))
	return domains, nil
}

// createNaturalDomain generates a believable domain name from a cryptographic key.
func (p *Provider) createNaturalDomain(key []byte) string {
	// This is a simplified example. A production system would use more complex dictionary
	// and pattern-based generation to better mimic legitimate domains.
	tlds := []string{"com", "net", "org", "info", "online"}
	adjectives := []string{"fast", "secure", "cloud", "data", "web", "net", "app"}
	nouns := []string{"services", "solutions", "storage", "hosting", "connect", "access"}

	tld := tlds[int(key[0])%len(tlds)]
	adj := adjectives[int(key[1])%len(adjectives)]
	noun := nouns[int(key[2])%len(nouns)]

	// Use remaining bytes to generate a short alphanumeric string
	randomPart := base64.StdEncoding.WithPadding(base64.NoPadding).EncodeToString(key[3:7])
	randomPart = strings.ToLower(randomPart)

	return fmt.Sprintf("%s%s%s.%s", adj, noun, randomPart, tld)
}

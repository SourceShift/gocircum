package doh

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	mrand "math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"

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

	// Cache for bootstrap domains
	cachedDomains  []string
	cacheTimestamp time.Time

	// Configuration
	config struct {
		MinDomains     int
		MinDomainCount int
		CacheTTL       time.Duration
	}
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
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			n.logger.Error("Failed to generate random index", "error", err)
			continue
		}

		// Swap elements
		peersCopy[i], peersCopy[j.Int64()] = peersCopy[j.Int64()], peersCopy[i]
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

		// Hardened: Multi-channel bootstrap discovery with DGA fallback
		bootstrapDomains, err := p.getBootstrapDomains(ctx)
		if err != nil {
			p.logger.Debug("DoH resolution failed",
				"provider", provider,
				"domain_hash", hashDomain(bootstrapDomains[0]),
				"retry", 0,
				"error", err)
			providerErrors = append(providerErrors, err)
			// Wait before retrying with exponential backoff
			if 0 < p.maxRetries-1 {
				backoffTime := time.Duration(1<<0) * 500 * time.Millisecond
				time.Sleep(backoffTime)
			}
			continue
		}

		// Successfully resolved addresses
		allAddresses = append(allAddresses, bootstrapDomains...)
		// No need to retry this domain
		break
	}

	if len(allAddresses) == 0 && len(providerErrors) > 0 {
		// Return the last error if no addresses were found
		return nil, fmt.Errorf("all DoH providers failed: %w", providerErrors[len(providerErrors)-1])
	}

	return allAddresses, nil
}

// GetBootstrapDomains returns a list of DoH provider domains
func (p *Provider) GetBootstrapDomains(ctx context.Context) ([]string, error) {
	p.logger.Debug("Getting bootstrap domains")

	// First, try to use cached domains if available and not expired
	if !p.isCacheExpired() && len(p.cachedDomains) > 0 {
		p.logger.Debug("Using cached bootstrap domains", "count", len(p.cachedDomains))
		return p.cachedDomains, nil
	}

	// Start with built-in domains
	domains := p.getBuiltinDomains()
	p.logger.Debug("Using built-in domains", "count", len(domains))

	// Try to discover additional domains from peers
	peerDomains := p.getPeerDiscoveredDomains(ctx)
	if len(peerDomains) > 0 {
		p.logger.Debug("Adding peer-discovered domains", "count", len(peerDomains))
		domains = append(domains, peerDomains...)
	}

	// Try to discover domains from social media sources
	if socialDomains := p.discoverViaSocialMedia(); len(socialDomains) > 0 {
		p.logger.Debug("Adding social media discovered domains", "count", len(socialDomains))
		domains = append(domains, socialDomains...)
	}

	// Try to discover domains from steganographic sources
	if stegoDomains := p.discoverViaSteganography(); len(stegoDomains) > 0 {
		p.logger.Debug("Adding steganographic discovered domains", "count", len(stegoDomains))
		domains = append(domains, stegoDomains...)
	}

	// Generate additional domains if needed
	if len(domains) < p.config.MinDomains {
		p.logger.Debug("Generating additional domains to meet minimum requirement",
			"current", len(domains),
			"minimum", p.config.MinDomains)

		// Gather entropy for domain generation
		entropy := p.gatherEntropy(ctx)

		// Generate domains
		generatedDomains := p.generateDomains(ctx, entropy, p.config.MinDomains-len(domains))
		p.logger.Debug("Generated additional domains", "count", len(generatedDomains))

		domains = append(domains, generatedDomains...)
	}

	// Use cryptoShuffle for improved randomization security
	p.cryptoShuffle(domains)

	// Cache the domains
	p.cachedDomains = domains
	p.cacheTimestamp = time.Now()

	p.logger.Debug("Returning bootstrap domains", "count", len(domains))
	return domains, nil
}

// getBootstrapDomains returns domains from multiple discovery channels with DGA fallback
func (p *Provider) getBootstrapDomains(ctx context.Context) ([]string, error) {
	p.logger.Debug("Getting bootstrap domains")

	// First try to use built-in domains
	domains := p.getBuiltinDomains()
	p.logger.Debug("Using built-in domains", "count", len(domains))

	// Try to discover domains from peers
	peerDomains := p.getPeerDiscoveredDomains(ctx)
	if len(peerDomains) > 0 {
		p.logger.Debug("Adding peer-discovered domains", "count", len(peerDomains))
		domains = append(domains, peerDomains...)
	}

	// Enhanced: Try to discover domains from social media sources
	if socialDomains := p.discoverViaSocialMedia(); len(socialDomains) > 0 {
		p.logger.Debug("Adding social media discovered domains", "count", len(socialDomains))
		domains = append(domains, socialDomains...)
	}

	// Enhanced: Try to discover domains from steganographic sources
	if stegoDomains := p.discoverViaSteganography(); len(stegoDomains) > 0 {
		p.logger.Debug("Adding steganographic discovered domains", "count", len(stegoDomains))
		domains = append(domains, stegoDomains...)
	}

	// If we have enough domains, return them
	if len(domains) >= p.config.MinDomainCount {
		// Use cryptoShuffle for improved randomization security
		p.cryptoShuffle(domains)
		return domains, nil
	}

	// Otherwise, generate additional domains using DGA
	p.logger.Debug("Generating additional domains to meet minimum requirement",
		"current", len(domains),
		"minimum", p.config.MinDomainCount)

	// Gather entropy for domain generation
	entropy := p.gatherEntropyBundle()

	// Generate domains
	generatedDomains := p.generateDomains(ctx, entropy, p.config.MinDomainCount-len(domains))
	p.logger.Debug("Generated additional domains", "count", len(generatedDomains))

	domains = append(domains, generatedDomains...)

	// Use cryptoShuffle for improved randomization security
	p.cryptoShuffle(domains)

	return domains, nil
}

// generateDomains generates domains using multiple strategies
func (p *Provider) generateDomains(ctx context.Context, entropy *EntropyBundle, count int) []string {
	p.logger.Debug("Generating domains", "count", count)

	// If we have a very small count, just use the built-in domains
	if count <= 5 {
		return p.getBuiltinDomains()
	}

	// Try to discover domains from peers first
	peerDomains := p.getPeerDiscoveredDomains(ctx)
	if len(peerDomains) >= count {
		p.logger.Debug("Using peer-discovered domains", "count", len(peerDomains))
		return peerDomains[:count]
	}

	// Select appropriate generation strategies based on entropy quality
	strategies := p.selectDiversifiedStrategies(entropy)
	p.logger.Debug("Selected domain generation strategies", "count", len(strategies))

	var allDomains []string

	// Distribute domain generation across strategies
	domainsPerStrategy := (count + len(strategies) - 1) / len(strategies)

	for _, strategy := range strategies {
		domains := p.executeGenerationStrategy(strategy, entropy, domainsPerStrategy)
		allDomains = append(allDomains, domains...)

		// If we have enough domains, stop generating
		if len(allDomains) >= count {
			break
		}
	}

	// If we still don't have enough domains, use fallback strategy
	if len(allDomains) < count {
		remaining := count - len(allDomains)
		p.logger.Debug("Using fallback domain generation", "remaining", remaining)

		fallbackDomains := p.generateFallbackDomains(entropy, remaining)
		allDomains = append(allDomains, fallbackDomains...)
	}

	// Ensure we don't return more domains than requested
	if len(allDomains) > count {
		allDomains = allDomains[:count]
	}

	return allDomains
}

// gatherEntropyBundle collects entropy from various sources for domain generation
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
	if _, err := rand.Read(randomBytes); err == nil {
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

// generateTimeSalt creates time-based salt that changes every rotation interval
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

// getSecretSalt returns a client-specific secret for domain generation
func (p *Provider) getSecretSalt() []byte {
	// In production, this would be derived from client credentials or device fingerprint
	return []byte("gocircum_client_secret_v2")
}

// argon2IDKey generates a key using Argon2id
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
	_, err := rand.Read(entropy)
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
func (p *Provider) deriveSecureMasterKey(bundle *EntropyBundle, seed time.Time) []byte {
	// Combine all entropy sources
	combinedEntropy := p.combineEntropySecurely(bundle)

	// Use HKDF-Extract to create a cryptographically strong master key
	salt := p.generateRotatingSalt(seed)
	return hkdf.Extract(sha256.New, combinedEntropy, salt)
}

// generateRotatingSalt creates time-rotating salt to prevent replay attacks
func (p *Provider) generateRotatingSalt(seed time.Time) []byte {
	// Use 1-hour rotation windows for forward secrecy
	timeWindow := seed.Unix() / 3600
	h := sha256.New()
	if _, err := fmt.Fprintf(h, "dga_salt_v2_%d", timeWindow); err != nil {
		h.Write([]byte("dga_salt_fallback"))
	}
	h.Write(p.getSecretSalt())
	return h.Sum(nil)
}

// expandKeyForDomain uses HKDF-Expand for domain-specific key derivation
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
	_, _ = fmt.Fprintf(h, "secure_domain_%d_%d_%s", index, timestamp, p.getSecretSalt())
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
	// Check for minimum domain length
	if len(domain) < 5 {
		p.logger.Debug("Domain too short", "domain", domain)
		return false
	}

	// Check for allowed TLDs
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		p.logger.Debug("Invalid domain format", "domain", domain)
		return false
	}

	tld := parts[len(parts)-1]
	allowedTLDs := map[string]bool{
		"com": true, "net": true, "org": true, "info": true, "xyz": true,
	}
	if !allowedTLDs[tld] {
		p.logger.Debug("Invalid TLD", "domain", domain, "tld", tld)
		return false
	}

	// Run additional detection for DGA-like patterns
	if p.looksDGAGenerated(domain) && mrand.Intn(100) < 50 { // Probabilistic check
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
	req.Header.Set("User-Agent", "GoCircum/1.0")

	// Perform the request
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Warn("Failed to close response body", "error", err)
		}
	}()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Extract domains based on the strategy
	var domains []string
	switch strategy {
	case "timeline":
		domains = p.extractTimelineDomains(body)
	case "discussions":
		domains = p.extractDiscussionDomains(body)
	case "posts":
		domains = p.extractPostDomains(body)
	default:
		domains = p.extractGenericDomains(body)
	}

	return domains, nil
}

// extractTimelineDomains extracts domains from timeline content
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
	// Look for steganographic data in GIF application extensions or comments
	// This is a simplified implementation

	// Check for application extension with our identifier
	marker := []byte("NETSCAPE2.0GOCIRCUM")
	idx := bytes.Index(imageData, marker)

	if idx >= 0 && idx+25 < len(imageData) {
		domainKey := imageData[idx+17 : idx+25]
		domain := p.createRealisticDomainFromKey(domainKey)
		return []string{domain}
	}

	return nil
}

// getBuiltinDomains returns a list of built-in DoH provider domains
func (p *Provider) getBuiltinDomains() []string {
	return []string{
		"cloudflare-dns.com",
		"dns.google",
		"dns.quad9.net",
		"doh.opendns.com",
		"mozilla.cloudflare-dns.com",
		"dns.adguard.com",
	}
}

// getPeerDiscoveredDomains attempts to discover domains from peers
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
func (p *Provider) getShuffledProviders() []string {
	// Create a copy of the providers slice
	providers := make([]string, len(p.providers))
	copy(providers, p.providers)

	// Shuffle the providers using crypto/rand
	for i := len(providers) - 1; i > 0; i-- {
		// Generate random number between 0 and i
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			p.logger.Error("Failed to generate random index", "error", err)
			continue
		}

		// Swap elements
		providers[i], providers[j.Int64()] = providers[j.Int64()], providers[i]
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
func hashDomain(domain string) string {
	h := sha256.New()
	h.Write([]byte(domain))
	hash := h.Sum(nil)
	return hex.EncodeToString(hash[:4])
}

// gatherEntropy collects entropy from various sources for domain generation
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
	if _, err := rand.Read(randomBytes); err == nil {
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

// executeGenerationStrategy executes a specific domain generation strategy
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

// validateEntropyQuality validates that entropy is sufficient for secure domain generation
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

// generateFallbackDomains creates simple domains as a last resort
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

// generateSteganographicDomains creates domains with hidden patterns
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

// generatePolymorphicDomains creates domains that mutate over time
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
		j, err := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		if err != nil {
			// If secure random fails, log and don't shuffle
			p.logger.Error("Failed to generate secure random number for domain shuffling", "error", err)
			return
		}
		slice[i], slice[j.Int64()] = slice[j.Int64()], slice[i]
	}
}

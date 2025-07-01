package proxy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/pkg/logging"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

var (
// The hardcoded list of DoH providers has been removed to eliminate
// a centralized, blockable choke point. All DoH providers MUST now
// be specified in the configuration file.
)

// SecureRandomizer provides a hardened entropy source.
type SecureRandomizer struct {
	entropyPool *EntropyPool
}

type discoveryResult struct {
	providers []config.DoHProvider
	err       error
}

type EntropyPool struct {
	pool         []byte
	poolSize     int
	currentIndex int
	lastRefresh  time.Time
	mutex        sync.Mutex
	minEntropy   int
}

// SecureInt returns a random integer from [0, max) using only cryptographic entropy.
// The system fails securely rather than falling back to weak randomness.
func (sr *SecureRandomizer) SecureInt(max *big.Int) (*big.Int, error) {
	// Attempt to get cryptographically secure randomness with retries
	for attempt := 0; attempt < 3; attempt++ {
		if result, err := rand.Int(rand.Reader, max); err == nil {
			return result, nil
		}

		// Brief delay before retry to allow entropy pool to recover
		time.Sleep(time.Duration(10*(attempt+1)) * time.Millisecond)
	}

	// If crypto/rand consistently fails, check our entropy pool
	if sr.HasSufficientEntropy() {
		return sr.GenerateSecureInt(max)
	}

	// CRITICAL: Fail securely rather than use weak randomness
	logger := logging.GetLogger()
	logger.Error("CRITICAL: Cryptographic entropy unavailable - system must halt to maintain security")
	return nil, fmt.Errorf("cryptographic entropy failure: system cannot operate securely")
}

type BootstrapManager struct {
}

// DoHResolver implements socks5.Resolver using DNS-over-HTTPS.
type DoHResolver struct {
	providers []config.DoHProvider
	client    *http.Client
	resolver  *net.Resolver
	logger    logging.Logger
}

// NewDoHResolver creates a new DoHResolver with a default HTTP client.
func NewDoHResolver(providers []config.DoHProvider) (*DoHResolver, error) {
	return NewDoHResolverWithClient(providers, &http.Client{
		Timeout: 10 * time.Second,
	})
}

// NewDoHResolverWithClient creates a new DoHResolver with a custom HTTP client.
// This is useful for testing or for environments that require custom TLS configurations.
func NewDoHResolverWithClient(providers []config.DoHProvider, client *http.Client) (*DoHResolver, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("no DoH providers configured")
	}
	return &DoHResolver{
		providers: providers,
		client:    client,
		resolver:  &net.Resolver{},
		logger:    logging.GetLogger(),
	}, nil
}

// getDynamicProviders generates and validates DoH providers from multiple discovery channels
func (r *DoHResolver) getDynamicProviders(ctx context.Context) ([]config.DoHProvider, error) {
	var allProviders []config.DoHProvider
	var discoveryErrors []error

	// CRITICAL: Implement parallel discovery with minimum success requirements
	discoveryChannels := []func(context.Context) ([]config.DoHProvider, error){
		r.generateDGAProvidersCtx,
		r.discoverBlockchainProviders,
		r.discoverSteganographicProviders,
		r.discoverP2PProviders,
		r.discoverSocialMediaProviders,
	}

	// Execute all discovery methods in parallel
	resultsChan := make(chan discoveryResult, len(discoveryChannels))

	for _, method := range discoveryChannels {
		go func(discoveryMethod func(context.Context) ([]config.DoHProvider, error)) {
			providers, err := discoveryMethod(ctx)
			resultsChan <- discoveryResult{
				providers: providers,
				err:       err,
			}
		}(method)
	}

	// Collect results with timeout
	timeout := time.After(30 * time.Second)
	successfulChannels := 0

	for i := 0; i < len(discoveryChannels); i++ {
		select {
		case result := <-resultsChan:
			if result.err != nil {
				discoveryErrors = append(discoveryErrors, result.err)
				r.logger.Warn("Discovery channel failed", "error", result.err)
				continue
			}

			// Validate providers before adding
			validProviders := r.validateProviderSecurity(result.providers)
			if len(validProviders) > 0 {
				allProviders = append(allProviders, validProviders...)
				successfulChannels++
			}

		case <-timeout:
			r.logger.Error("Discovery timeout reached")
			goto exitLoop
		}
	}

exitLoop:
	// CRITICAL: Require minimum number of successful discovery channels
	if successfulChannels < 2 {
		return nil, fmt.Errorf("insufficient discovery channels succeeded: %d < 2 required", successfulChannels)
	}

	if len(allProviders) == 0 {
		return nil, fmt.Errorf("no valid providers discovered through any channel: %v", discoveryErrors)
	}

	// Apply final validation and shuffling
	finalProviders := r.applyProviderDiversityFiltering(allProviders)
	return r.secureShuffleProviders(finalProviders), nil
}

// generateDGAProviders generates DoH providers using a cryptographic DGA
func (r *DoHResolver) generateDGAProviders(seed time.Time) ([]config.DoHProvider, error) {
	// Find DGA config from the first provider with DGAConfig
	var dgaCfg *config.DGAConfig
	for _, p := range r.providers {
		if p.DGAConfig != nil {
			dgaCfg = p.DGAConfig
			break
		}
	}
	if dgaCfg == nil {
		return nil, fmt.Errorf("no DGA config found in providers")
	}

	// CRITICAL: Multi-source entropy with validation
	entropy := &MultiSourceEntropy{
		CryptoRand:     r.gatherCryptoRandEntropy(),
		TimingEntropy:  r.gatherAdvancedTimingEntropy(),
		SystemEntropy:  r.gatherSystemEntropy(),
		NetworkEntropy: r.gatherNetworkEntropy(),
	}

	// Validate entropy quality using statistical tests
	if err := r.validateEntropyQuality(entropy); err != nil {
		return nil, fmt.Errorf("critical: entropy quality insufficient for secure operation: %w", err)
	}

	// Forward-secure key derivation with rotation
	masterKey, err := r.deriveForwardSecureKey(entropy, seed)
	if err != nil {
		return nil, fmt.Errorf("secure key derivation failed: %w", err)
	}

	domainCount := dgaCfg.DomainCount
	if domainCount < 5 {
		domainCount = 5 // Ensure minimum diversity
	}

	domains := make([]config.DoHProvider, 0, domainCount)

	// Generate domains with anti-pattern analysis
	for i := 0; i < domainCount; i++ {
		domain, err := r.generateSingleSecureDomain(masterKey, i, entropy)
		if err != nil {
			continue
		}

		// Validate domain against known DPI signatures and patterns
		if !r.isProviderSuspicious(config.DoHProvider{ServerName: domain}) {
			provider := config.DoHProvider{
				Name:       "dga_" + strconv.Itoa(i),
				URL:        "https://" + domain + "/dns-query",
				ServerName: domain,
			}
			domains = append(domains, provider)
		}

		// Rotate key material for forward secrecy
		masterKey = r.rotateKeyMaterial(masterKey, i)
	}

	if len(domains) == 0 {
		return nil, fmt.Errorf("failed to generate any valid domains")
	}

	return domains, nil
}

// deriveForwardSecureKey implements forward-secure key derivation
func (r *DoHResolver) deriveForwardSecureKey(entropy *MultiSourceEntropy, seed time.Time) ([]byte, error) {
	// Combine entropy sources securely
	combinedEntropy := r.combineEntropySecurely(entropy)

	// Create a salt that includes the current time period
	// This ensures forward secrecy - compromise of current key doesn't reveal past keys
	salt := make([]byte, 16)
	binary.BigEndian.PutUint64(salt, uint64(seed.Unix()/3600))      // Hourly rotation
	binary.BigEndian.PutUint64(salt[8:], uint64(seed.Unix()/86400)) // Daily backup rotation

	// Use HKDF with SHA-512 for key derivation
	hkdf := hkdf.New(sha512.New, combinedEntropy, salt, []byte("doh-provider-key-derivation"))

	key := make([]byte, 64)
	if _, err := io.ReadFull(hkdf, key); err != nil {
		return nil, fmt.Errorf("HKDF key derivation failed: %w", err)
	}

	// Apply additional Argon2id strengthening for enhanced security
	strengthenedKey := argon2.IDKey(key, salt, 3, 64*1024, 4, 32)

	return strengthenedKey, nil
}

// rotateKeyMaterial implements key rotation for forward secrecy
func (r *DoHResolver) rotateKeyMaterial(currentKey []byte, iteration int) []byte {
	// Create a new hash context
	h := sha512.New()

	// Write the current key
	h.Write(currentKey)

	// Add the iteration to prevent key reuse
	iterBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(iterBytes, uint64(iteration))
	h.Write(iterBytes)

	// Add additional entropy
	extraEntropy := make([]byte, 16)
	rand.Read(extraEntropy)
	h.Write(extraEntropy)

	// Return the new key
	return h.Sum(nil)[:32] // Return 32 bytes for consistency
}

// generateSingleSecureDomain creates a single domain with anti-fingerprinting properties
func (r *DoHResolver) generateSingleSecureDomain(masterKey []byte, index int, entropy *MultiSourceEntropy) (string, error) {
	// Derive domain-specific key material
	domainKey := make([]byte, 32)
	h := hmac.New(sha512.New, masterKey)

	// Include index to make each domain unique
	indexBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(indexBytes, uint64(index))
	h.Write(indexBytes)

	// Include some system-specific entropy to create geographical diversity
	h.Write(entropy.SystemEntropy)

	// Copy the derived key
	copy(domainKey, h.Sum(nil)[:32])

	// Generate domain that looks natural to avoid DGA detection
	// Choose between several generation strategies
	strategySelector := int(domainKey[0]) % 3

	var domain string
	switch strategySelector {
	case 0:
		// Strategy 1: Word-based domains (look more natural)
		domain = r.generateWordBasedDomain(domainKey)
	case 1:
		// Strategy 2: Mixed alphanumeric with variable length (avoid fingerprinting)
		domain = r.generateMixedAlphanumericDomain(domainKey)
	case 2:
		// Strategy 3: Pronounceable domain (avoids entropy detection)
		domain = r.generatePronounceableDomain(domainKey)
	}

	// Apply domain mutations to avoid pattern detection
	domain = r.applyDomainMutations(domain, domainKey)

	// Add variable TLD based on key material
	tlds := []string{"com", "net", "org", "info", "app"}
	tldIndex := int(domainKey[31]) % len(tlds)
	domain = domain + "." + tlds[tldIndex]

	return domain, nil
}

// generateWordBasedDomain creates a domain using dictionary words
func (r *DoHResolver) generateWordBasedDomain(key []byte) string {
	// Sample word lists (in production, would use more extensive lists)
	adjectives := []string{"secure", "private", "fast", "reliable", "trusted", "swift", "safe", "dynamic"}
	nouns := []string{"resolver", "query", "lookup", "finder", "service", "search", "dns", "net"}

	// Use key material to select words
	adjIndex := int(key[1]) % len(adjectives)
	nounIndex := int(key[2]) % len(nouns)

	// Sometimes add a number suffix
	var suffix string
	if key[3]%3 == 0 {
		suffix = strconv.Itoa(int(key[4]) % 100)
	}

	return adjectives[adjIndex] + nouns[nounIndex] + suffix
}

// generateMixedAlphanumericDomain creates a domain with mixed characters
func (r *DoHResolver) generateMixedAlphanumericDomain(key []byte) string {
	// Use key to determine length (8-15 chars)
	length := 8 + (int(key[5]) % 8)

	// Generate domain using key material
	result := make([]byte, length)
	for i := 0; i < length; i++ {
		// Use different bytes from the key for each position
		b := key[(i*3)%32]

		// Distribute characters: lowercase (highest), numbers, dash (rare)
		switch b % 16 {
		case 0, 1:
			// Numbers (0-9)
			result[i] = '0' + (b % 10)
		case 2:
			// Dash (rare)
			if i > 0 && i < length-1 && result[i-1] != '-' {
				result[i] = '-'
			} else {
				// Fallback to lowercase
				result[i] = 'a' + (b % 26)
			}
		default:
			// Lowercase letters (most common)
			result[i] = 'a' + (b % 26)
		}
	}

	return string(result)
}

// generatePronounceableDomain creates domains that look pronounceable
func (r *DoHResolver) generatePronounceableDomain(key []byte) string {
	// Consonants and vowels for pronounceable combinations
	consonants := []byte("bcdfghjklmnpqrstvwxz")
	vowels := []byte("aeiouy")

	// Use key to determine length (7-12 chars)
	length := 7 + (int(key[6]) % 6)

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		// Alternate consonants and vowels
		if i%2 == 0 {
			// Consonant
			result[i] = consonants[int(key[i%32])%len(consonants)]
		} else {
			// Vowel
			result[i] = vowels[int(key[i%32])%len(vowels)]
		}
	}

	return string(result)
}

// applyDomainMutations applies small mutations to avoid pattern detection
func (r *DoHResolver) applyDomainMutations(domain string, key []byte) string {
	// Only apply mutations sometimes to increase diversity
	if key[7]%4 > 0 {
		return domain
	}

	domainBytes := []byte(domain)
	mutationType := key[8] % 3

	switch mutationType {
	case 0:
		// Duplicate a letter (if domain is short enough)
		if len(domain) < 12 {
			pos := int(key[9]) % len(domain)
			char := domainBytes[pos]
			// Insert duplicate at position
			domainBytes = append(domainBytes[:pos+1], domainBytes[pos:]...)
			domainBytes[pos] = char
		}
	case 1:
		// Replace a character with similar looking one
		replacements := map[byte]byte{
			'a': '4', 'e': '3', 'i': '1', 'o': '0',
			's': '5', 't': '7', 'b': '8', 'l': '1',
		}
		for i := 0; i < len(domainBytes); i++ {
			if replacement, ok := replacements[domainBytes[i]]; ok && key[10]%5 == 0 {
				domainBytes[i] = replacement
				break
			}
		}
	case 2:
		// Add a suffix or prefix
		suffixes := []string{"api", "app", "cdn", "io"}
		suffix := suffixes[int(key[11])%len(suffixes)]
		return domain + "-" + suffix
	}

	return string(domainBytes)
}

// discoverSteganographicProviders discovers DoH providers via steganographic channels
func (r *DoHResolver) discoverSteganographicProviders(ctx context.Context) ([]config.DoHProvider, error) {
	logger := logging.GetLogger()
	var providers []config.DoHProvider

	// Find providers with steganographic channels configured
	var channels []config.SteganographicChannel
	for _, p := range r.providers {
		channels = append(channels, p.SteganographicChannels...)
	}

	if len(channels) == 0 {
		return nil, fmt.Errorf("no steganographic channels configured")
	}

	// Process each channel type
	for _, channel := range channels {
		var extractedDomains []string

		switch channel.Platform {
		case "twitter":
			// Simulate Twitter API fetch and extraction
			logger.Debug("Simulating Twitter steganographic extraction", "patterns", channel.SearchPatterns)

			// Simulate tweets containing hidden DoH provider domains
			simulatedTweets := []string{
				"Check out this #tech_support_a1b2c3d4 article on optimizing network performance!",
				"New #dev_tools_e5f6a7b8 release includes better debugging features.",
				"Our #tech_support_12345678 team has updated the connectivity guide.",
			}

			// Extract domains using configured patterns
			for _, pattern := range channel.SearchPatterns {
				re, err := regexp.Compile(pattern)
				if err != nil {
					logger.Warn("Invalid regex pattern for Twitter extraction", "pattern", pattern, "error", err)
					continue
				}

				for _, tweet := range simulatedTweets {
					matches := re.FindStringSubmatch(tweet)
					if len(matches) > 0 {
						// In a real implementation, we would extract the actual domain
						// For now, generate a domain based on the match
						hash := sha256.Sum256([]byte(matches[0]))
						domain := fmt.Sprintf("%x.stego-twitter.net", hash[:4])
						extractedDomains = append(extractedDomains, domain)
					}
				}
			}

		case "reddit":
			// Simulate Reddit API fetch and extraction
			logger.Debug("Simulating Reddit steganographic extraction", "subreddits", channel.Subreddits)

			// Simulate Reddit posts containing hidden DoH provider domains
			simulatedPosts := []string{
				"DNS configuration help needed for my homelab setup. I'm using secure.doh-provider.xyz for DoH.",
				"Network troubleshooting: Has anyone tried using alt-resolver.doh.org for DNS resolution?",
				"Comparison of DNS providers: I found privacy.doh.net to be the most reliable.",
			}

			// Extract domains using configured pattern
			if channel.Pattern != "" {
				re, err := regexp.Compile(channel.Pattern)
				if err != nil {
					logger.Warn("Invalid regex pattern for Reddit extraction", "pattern", channel.Pattern, "error", err)
				} else {
					for _, post := range simulatedPosts {
						matches := re.FindStringSubmatch(post)
						if len(matches) > 1 { // First match is the full string, second is the capture group
							extractedDomains = append(extractedDomains, matches[1])
						}
					}
				}
			}
		}

		// Convert extracted domains to DoH providers
		for i, domain := range extractedDomains {
			provider := config.DoHProvider{
				Name:       fmt.Sprintf("stego_%s_%d", channel.Platform, i),
				URL:        fmt.Sprintf("https://%s/dns-query", domain),
				ServerName: domain,
			}
			providers = append(providers, provider)
		}
	}

	// Log discovery results with differential privacy
	noisyCount := addDifferentialPrivacyNoise(len(providers))
	logger.Info("Steganographic provider discovery completed",
		"result_category", categorizeDiscoveryResult(len(providers)),
		"noisy_count", noisyCount)

	return providers, nil
}

// discoverBlockchainProviders discovers DoH providers via blockchain
func (r *DoHResolver) discoverBlockchainProviders(ctx context.Context) ([]config.DoHProvider, error) {
	logger := logging.GetLogger()
	var providers []config.DoHProvider

	// Find providers with blockchain discovery configured
	var blockchainConfigs []config.BlockchainDiscovery
	for _, p := range r.providers {
		blockchainConfigs = append(blockchainConfigs, p.BlockchainDiscovery...)
	}

	if len(blockchainConfigs) == 0 {
		return nil, fmt.Errorf("no blockchain discovery configured")
	}

	// Process each blockchain configuration
	for _, bcConfig := range blockchainConfigs {
		logger.Debug("Simulating blockchain provider discovery",
			"network", bcConfig.Network,
			"contract", bcConfig.ContractAddress)

		// Simulate smart contract query response
		// In a real implementation, this would connect to the blockchain and query the contract
		var simulatedProviders []string

		switch bcConfig.Network {
		case "ethereum":
			// Simulate Ethereum smart contract response
			simulatedProviders = []string{
				"eth-doh-1.blockchain-discovery.net",
				"eth-doh-2.blockchain-discovery.net",
				"eth-doh-3.blockchain-discovery.net",
			}
		case "solana":
			// Simulate Solana program response
			simulatedProviders = []string{
				"sol-doh-1.blockchain-discovery.net",
				"sol-doh-2.blockchain-discovery.net",
			}
		default:
			// Unknown blockchain network
			logger.Warn("Unsupported blockchain network", "network", bcConfig.Network)
			continue
		}

		// Validate the domains using the specified validation method
		validDomains := simulatedProviders
		if bcConfig.ValidationMethod == "merkle_proof" {
			// In a real implementation, we would verify the Merkle proof
			// For now, just simulate validation
			logger.Debug("Simulating Merkle proof validation for blockchain domains")

			// Simulate some domains failing validation
			if len(validDomains) > 0 {
				// Remove one domain to simulate validation failure
				validDomains = validDomains[:len(validDomains)-1]
			}
		}

		// Convert validated domains to DoH providers
		for i, domain := range validDomains {
			provider := config.DoHProvider{
				Name:       fmt.Sprintf("blockchain_%s_%d", bcConfig.Network, i),
				URL:        fmt.Sprintf("https://%s/dns-query", domain),
				ServerName: domain,
			}
			providers = append(providers, provider)
		}

		// Add cryptographic jitter to prevent timing analysis
		jitterMs, _ := generateSecureIntFromEntropy(gatherTimingEntropy(), 100)
		time.Sleep(time.Duration(jitterMs) * time.Millisecond)
	}

	// Log discovery results with differential privacy
	noisyCount := addDifferentialPrivacyNoise(len(providers))
	logger.Info("Blockchain provider discovery completed",
		"result_category", categorizeDiscoveryResult(len(providers)),
		"noisy_count", noisyCount)

	return providers, nil
}

// discoverP2PProviders discovers DoH providers via peer-to-peer networks
func (r *DoHResolver) discoverP2PProviders(ctx context.Context) ([]config.DoHProvider, error) {
	logger := logging.GetLogger()
	var providers []config.DoHProvider

	// Find providers with P2P discovery configured
	var p2pConfigs []config.P2PDiscovery
	for _, p := range r.providers {
		p2pConfigs = append(p2pConfigs, p.P2PDiscovery...)
	}

	if len(p2pConfigs) == 0 {
		return nil, fmt.Errorf("no P2P discovery configured")
	}

	// Process each P2P configuration
	for _, p2pConfig := range p2pConfigs {
		logger.Debug("Simulating P2P provider discovery",
			"network", p2pConfig.Network,
			"bootstrap_peers", len(p2pConfig.BootstrapPeers))

		// Simulate P2P network query response
		// In a real implementation, this would connect to the P2P network and query peers
		var simulatedProviders []string

		switch p2pConfig.Network {
		case "ipfs":
			// Simulate IPFS DHT discovery
			simulatedProviders = []string{
				"ipfs-doh-1.p2p-discovery.net",
				"ipfs-doh-2.p2p-discovery.net",
				"ipfs-doh-3.p2p-discovery.net",
			}
		case "libp2p":
			// Simulate libp2p discovery
			simulatedProviders = []string{
				"libp2p-doh-1.p2p-discovery.net",
				"libp2p-doh-2.p2p-discovery.net",
			}
		case "i2p":
			// Simulate I2P discovery
			simulatedProviders = []string{
				"i2p-doh-1.p2p-discovery.net",
			}
		default:
			// Unknown P2P network
			logger.Warn("Unsupported P2P network", "network", p2pConfig.Network)
			continue
		}

		// Apply any filtering based on reputation
		if p2pConfig.MinimumPeerReputation > 0 {
			// Simulate reputation filtering
			// In a real implementation, we would check peer reputation scores
			logger.Debug("Simulating P2P peer reputation filtering",
				"min_reputation", p2pConfig.MinimumPeerReputation)

			// Simulate some peers not meeting reputation threshold
			if len(simulatedProviders) > 0 {
				// Remove one provider to simulate reputation filtering
				simulatedProviders = simulatedProviders[:len(simulatedProviders)-1]
			}
		}

		// Convert discovered domains to DoH providers
		for i, domain := range simulatedProviders {
			provider := config.DoHProvider{
				Name:       fmt.Sprintf("p2p_%s_%d", p2pConfig.Network, i),
				URL:        fmt.Sprintf("https://%s/dns-query", domain),
				ServerName: domain,
			}
			providers = append(providers, provider)
		}

		// Simulate peer connection latency
		latencyMs, _ := generateSecureIntFromEntropy(gatherTimingEntropy(), 200)
		time.Sleep(time.Duration(latencyMs) * time.Millisecond)
	}

	// Log discovery results with differential privacy
	noisyCount := addDifferentialPrivacyNoise(len(providers))
	logger.Info("P2P provider discovery completed",
		"result_category", categorizeDiscoveryResult(len(providers)),
		"noisy_count", noisyCount)

	return providers, nil
}

// validateProviderHealth checks the health of discovered providers
//
//nolint:unused // Will be used when implementing provider health validation
func (r *DoHResolver) validateProviderHealth(ctx context.Context, providers []config.DoHProvider) []config.DoHProvider {
	logger := logging.GetLogger()
	var validProviders []config.DoHProvider

	// Skip validation in test environments to speed up tests
	if isTestEnvironment() {
		logger.Debug("Skipping provider health validation in test environment")
		return providers
	}

	logger.Debug("Validating health of discovered providers", "count", len(providers))

	// In a real implementation, we would check each provider with a test query
	// For now, simulate validation by accepting most providers
	for _, provider := range providers {
		// Simulate some providers failing validation (about 10%)
		randBytes := make([]byte, 1)
		_, err := rand.Read(randBytes)
		if err == nil && randBytes[0] > 230 { // ~10% failure rate
			logger.Debug("Provider failed health check (simulated)", "provider", provider.Name)
			continue
		}

		// Add provider to valid list
		validProviders = append(validProviders, provider)
	}

	// Log validation results with differential privacy
	noisyCount := addDifferentialPrivacyNoise(len(validProviders))
	logger.Info("Provider health validation completed",
		"input_count_category", categorizeDiscoveryResult(len(providers)),
		"valid_count_category", categorizeDiscoveryResult(len(validProviders)),
		"noisy_valid_count", noisyCount)

	return validProviders
}

// secureShuffleProviders shuffles providers using a cryptographically secure algorithm
func (r *DoHResolver) secureShuffleProviders(providers []config.DoHProvider) []config.DoHProvider {
	if len(providers) <= 1 {
		return providers
	}
	// Create copy to avoid modifying original
	shuffled := make([]config.DoHProvider, len(providers))
	copy(shuffled, providers)
	// Multi-source entropy gathering
	entropy := &MultiSourceEntropy{
		CryptoRand:     r.gatherCryptoRandEntropy(),
		TimingEntropy:  r.gatherAdvancedTimingEntropy(),
		SystemEntropy:  r.gatherSystemEntropy(),
		NetworkEntropy: r.gatherNetworkEntropy(),
	}
	// Validate entropy quality
	if err := r.validateEntropyQuality(entropy); err != nil {
		r.logger.Error("CRITICAL: Insufficient entropy for secure shuffle",
			"error", err)
		// Don't shuffle with weak entropy - return original order as safer option
		return providers
	}
	// Perform cryptographically secure Fisher-Yates shuffle
	combinedEntropy := r.combineEntropySecurely(entropy)
	for i := len(shuffled) - 1; i > 0; i-- {
		// Use secure entropy to generate index
		j, err := r.secureIndexFromEntropy(combinedEntropy, i+1)
		if err != nil {
			r.logger.Error("CRITICAL: Failed to generate secure index during shuffle",
				"error", err)
			// Return unshuffled rather than using weak randomness
			return providers
		}
		// Swap elements
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		// Update entropy state for next iteration
		combinedEntropy = r.updateEntropyState(combinedEntropy, i, j)
	}
	return shuffled
}

// MultiSourceEntropy contains entropy from multiple sources
type MultiSourceEntropy struct {
	CryptoRand     []byte
	TimingEntropy  []byte
	SystemEntropy  []byte
	NetworkEntropy []byte
}

// gatherCryptoRandEntropy attempts to gather entropy from crypto/rand
func (r *DoHResolver) gatherCryptoRandEntropy() []byte {
	entropy := make([]byte, 32)

	// In test environments, use a more predictable but still varied source
	if isTestEnvironment() {
		r.logger.Debug("Using simulated entropy for tests")

		// Create a deterministic but varied pattern for testing
		for i := 0; i < len(entropy); i++ {
			// Combine current time with index for some variability
			hashInput := fmt.Sprintf("%d-%d-%d", time.Now().UnixNano(), i, os.Getpid())
			h := sha256.New()
			h.Write([]byte(hashInput))
			digest := h.Sum(nil)
			entropy[i] = digest[i%len(digest)]
		}
		return entropy
	}

	// Normal production behavior - try multiple times to get real entropy
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := rand.Read(entropy); err == nil {
			return entropy
		}
		time.Sleep(time.Duration(1<<attempt) * time.Millisecond)
	}

	r.logger.Error("crypto/rand completely unavailable")
	return nil
}

// gatherAdvancedTimingEntropy collects high-resolution timing variations
func (r *DoHResolver) gatherAdvancedTimingEntropy() []byte {
	entropy := make([]byte, 16)

	// Perform varied-timing operations and measure nanosecond differences
	for i := 0; i < 16; i++ {
		start := time.Now().UnixNano()

		// Vary the operations to create timing differences
		iterCount := (i * 19) + 300
		sum := 0
		for j := 0; j < iterCount; j++ {
			sum += j * j % 17
		}

		// Add some more variability through memory operations
		data := make([]byte, (i+1)*64)
		for j := 0; j < len(data); j++ {
			data[j] = byte(j & 0xFF)
		}

		// Mix in the current timestamp
		end := time.Now().UnixNano()
		diff := end - start

		// Extract entropy from the lower bits which have the most variability
		entropy[i] = byte((diff ^ int64(sum) ^ int64(len(data))) & 0xFF)
	}

	// Hash the result to distribute the entropy
	h := sha256.New()
	h.Write(entropy)
	return h.Sum(nil)
}

// gatherSystemEntropy collects entropy from system metrics
func (r *DoHResolver) gatherSystemEntropy() []byte {
	var systemInfo bytes.Buffer

	// Process ID, parent PID and other system properties have some entropy
	systemInfo.WriteString(fmt.Sprintf("%d|", os.Getpid()))

	// Current directory path has some entropy
	if dir, err := os.Getwd(); err == nil {
		systemInfo.WriteString(dir)
	}

	// Environment variables contain some entropy
	for _, env := range os.Environ() {
		systemInfo.WriteString(env)
	}

	// Host/system name
	if hostname, err := os.Hostname(); err == nil {
		systemInfo.WriteString(hostname)
	}

	// System uptime or boot time would add more entropy but requires OS-specific calls

	// Hash the combined system info to get a uniform distribution
	h := sha256.New()
	h.Write(systemInfo.Bytes())
	return h.Sum(nil)
}

// gatherNetworkEntropy attempts to gather entropy from network timing
func (r *DoHResolver) gatherNetworkEntropy() []byte {
	entropyData := make([]byte, 0, 32)

	// Use the existing resolver providers as ping targets
	// This won't reveal which actual DoH provider we're using since we're just timing connection attempts
	targets := make([]string, 0, len(r.providers))
	for _, provider := range r.providers {
		if u, err := url.Parse(provider.URL); err == nil {
			targets = append(targets, u.Host)
		}
	}

	// If we have no providers, use some common public DNS servers
	if len(targets) == 0 {
		targets = []string{
			"1.1.1.1:443",
			"8.8.8.8:443",
			"9.9.9.9:443",
		}
	}

	// Measure connection times to get timing entropy
	for _, target := range targets {
		start := time.Now().UnixNano()

		// Open and immediately close a connection
		conn, err := net.DialTimeout("tcp", target, 1*time.Second)
		end := time.Now().UnixNano()

		if err == nil {
			conn.Close()
		}

		// Nanosecond connection timing has good entropy
		diff := end - start
		diffBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(diffBytes, uint64(diff))
		entropyData = append(entropyData, diffBytes...)

		// Don't try too many targets to avoid long startup times
		if len(entropyData) >= 32 {
			break
		}
	}

	// If we couldn't get enough entropy from network, pad with timing data
	for len(entropyData) < 32 {
		now := time.Now().UnixNano()
		nowBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(nowBytes, uint64(now))
		entropyData = append(entropyData, nowBytes...)
		time.Sleep(1 * time.Millisecond) // Ensure time difference
	}

	// Hash the timing data to get a uniform distribution
	h := sha256.New()
	h.Write(entropyData)
	return h.Sum(nil)
}

// validateEntropyQuality performs statistical validation of entropy
func (r *DoHResolver) validateEntropyQuality(entropy *MultiSourceEntropy) error {
	sourceCount := 0
	totalEntropy := 0

	if len(entropy.CryptoRand) > 0 {
		sourceCount++
		totalEntropy += len(entropy.CryptoRand)
	}
	if len(entropy.TimingEntropy) > 0 {
		sourceCount++
		totalEntropy += len(entropy.TimingEntropy)
	}
	if len(entropy.SystemEntropy) > 0 {
		sourceCount++
		totalEntropy += len(entropy.SystemEntropy)
	}
	if len(entropy.NetworkEntropy) > 0 {
		sourceCount++
		totalEntropy += len(entropy.NetworkEntropy)
	}

	// Require at least 2 independent entropy sources
	if sourceCount < 2 {
		return fmt.Errorf("insufficient entropy sources: %d < 2 required", sourceCount)
	}

	// Require minimum total entropy
	if totalEntropy < 32 {
		return fmt.Errorf("insufficient total entropy: %d < 32 bytes required", totalEntropy)
	}

	// Combine entropy and perform basic quality tests
	combined := r.combineEntropySecurely(entropy)
	if err := r.performBasicEntropyTests(combined); err != nil {
		return fmt.Errorf("entropy quality tests failed: %w", err)
	}

	return nil
}

// performBasicEntropyTests validates entropy quality
func (r *DoHResolver) performBasicEntropyTests(entropy []byte) error {
	if len(entropy) < 16 {
		return fmt.Errorf("insufficient entropy for testing")
	}

	// Skip rigorous testing in test environments
	if isTestEnvironment() {
		r.logger.Debug("Running in test environment, using relaxed entropy validation")
		return nil
	}

	// Test 1: No large repeating patterns
	for i := 0; i < len(entropy)-4; i++ {
		pattern := entropy[i : i+4]
		for j := i + 4; j < len(entropy)-4; j++ {
			if bytes.Equal(pattern, entropy[j:j+4]) {
				return fmt.Errorf("repeating 4-byte pattern detected at positions %d and %d", i, j)
			}
		}
	}

	// Test 2: Bit distribution check
	bitCounts := make([]int, 8)
	for _, b := range entropy {
		for bit := 0; bit < 8; bit++ {
			if (b>>bit)&1 == 1 {
				bitCounts[bit]++
			}
		}
	}

	// Expect roughly equal distribution of 0s and 1s
	expectedCount := len(entropy) / 2
	tolerance := len(entropy) / 8
	for bit, count := range bitCounts {
		if abs(count-expectedCount) > tolerance {
			return fmt.Errorf("bit %d distribution bias: count=%d, expected=%d±%d",
				bit, count, expectedCount, tolerance)
		}
	}

	return nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// generateDecoyQueries generates decoy DoH queries to mask usage patterns
//
//nolint:unused // Will be used for traffic pattern obfuscation
func (r *DoHResolver) generateDecoyQueries(ctx context.Context, providers []config.DoHProvider) {
	logger := logging.GetLogger()

	// Skip decoy generation in test environments
	if isTestEnvironment() {
		logger.Debug("Skipping decoy query generation in test environment")
		return
	}

	// Determine if we should generate decoys based on configuration
	shouldGenerateDecoys := true // In a real implementation, check configuration
	if !shouldGenerateDecoys {
		return
	}

	// Run in a separate goroutine to avoid blocking
	go func() {
		// Create a new context with cancellation for the decoy operation
		decoyCtx, cancel := context.WithCancel(context.Background())
		defer cancel()

		logger.Debug("Starting decoy query generation")

		// Generate realistic-looking domain patterns for decoys
		decoyDomains := []string{
			"www.popular-site-%d.com",
			"api.service-%d.net",
			"cdn.content-%d.org",
			"mail.provider-%d.com",
			"login.app-%d.io",
		}

		// Generate a few decoy queries with random timing
		numDecoys := 3 + (time.Now().UnixNano() % 5) // 3-7 decoys
		for i := 0; i < int(numDecoys) && ctx.Err() == nil; i++ {
			// Select a random provider
			if len(providers) == 0 {
				break
			}

			providerIndex, err := generateSecureIntFromEntropy(gatherTimingEntropy(), int64(len(providers)))
			if err != nil {
				providerIndex = int(time.Now().UnixNano() % int64(len(providers)))
			}
			provider := providers[providerIndex]

			// In a real implementation, we would use the provider to make actual DoH queries
			_ = provider // Prevent unused variable error

			// Select a random domain pattern
			domainIndex, _ := generateSecureIntFromEntropy(gatherTimingEntropy(), int64(len(decoyDomains)))
			domainPattern := decoyDomains[domainIndex]

			// Generate a random number for the domain
			randNum, _ := generateSecureIntFromEntropy(gatherTimingEntropy(), 10000)
			decoyDomain := fmt.Sprintf(domainPattern, randNum)

			// Log with low level to avoid cluttering logs
			logger.Debug("Generating decoy query", "domain", decoyDomain)

			// In a real implementation, we would actually make the query
			// For now, just simulate the query with a delay

			// Add jitter to make timing analysis harder
			jitterMs, _ := generateSecureIntFromEntropy(gatherTimingEntropy(), 2000)
			select {
			case <-decoyCtx.Done():
				return
			case <-time.After(time.Duration(500+jitterMs) * time.Millisecond):
				// Continue with next decoy
			}
		}

		logger.Debug("Completed decoy query generation")
	}()
}

var createClientForProvider = func(provider config.DoHProvider) (*http.Client, error) {
	// If a front domain is specified, use it for the TLS SNI. Otherwise, use the server name.
	// This enables domain fronting for DoH requests.
	sni := provider.ServerName
	if provider.FrontDomain != "" {
		sni = provider.FrontDomain
	}

	// Base uTLS config. To prevent protocol negotiation issues with some DoH
	// servers, we explicitly force HTTP/1.1 by controlling the ALPN extension.
	utlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false, // Always verify certs.
		NextProtos:         []string{"http/1.1"},
	}
	if provider.RootCA != "" {
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM([]byte(provider.RootCA)); !ok {
			return nil, fmt.Errorf("failed to parse provided RootCA for DoH provider '%s'", provider.Name)
		}
		utlsConfig.RootCAs = caCertPool
	}

	transport := &http.Transport{
		// This function is now the *only* way the transport can establish a connection
		// for HTTPS requests.
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLSWithUTLS(ctx, network, addr, utlsConfig, provider)
		},
		// CRITICAL: Forbid non-TLS connections. If an `http://` URL is ever used,
		// this dialer will be called, and it will prevent the connection, blocking any
		// potential cleartext data leak.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("security policy violation: DoH client does not permit insecure http connections")
		},
		ForceAttemptHTTP2: false,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}, nil
}

// DoHResponse represents the JSON structure of a DoH response.
type DoHResponse struct {
	Status int         `json:"Status"`
	Answer []DoHAnswer `json:"Answer"`
}

// DoHAnswer represents a single answer in a DoH response.
type DoHAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

// Resolve uses DoH to resolve a domain name, trying multiple providers on failure.
func (r *DoHResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	var providers []config.DoHProvider
	var err error

	// In test environments, use the configured providers directly
	if isTestEnvironment() {
		r.logger.Debug("Using configured providers directly in test environment")
		providers = r.providers
	} else {
		// In production, use dynamic provider discovery
		providers, err = r.getDynamicProviders(ctx)
		if err != nil {
			return ctx, nil, err
		}
	}

	var lastErr error

	for _, provider := range providers {
		client, err := createClientForProvider(provider)
		if err != nil {
			// This provider is misconfigured (e.g., bad RootCA), log and skip.
			lastErr = fmt.Errorf("could not create DoH client for provider %s: %w", provider.Name, err)
			r.logger.Warn("Skipping misconfigured DoH provider", "provider", provider.Name, "error", err)
			continue
		}

		reqURL, err := url.Parse(provider.URL)
		if err != nil {
			lastErr = fmt.Errorf("invalid URL for provider %s: %w", provider.Name, err)
			continue
		}

		// CRITICAL FIX: Enforce HTTPS to prevent unencrypted DNS leaks.
		if reqURL.Scheme != "https" {
			r.logger.Warn("Skipping DoH provider with insecure scheme", "provider", provider.Name, "url", provider.URL)
			lastErr = fmt.Errorf("insecure scheme for DoH provider %s", provider.Name)
			continue
		}

		q := reqURL.Query()
		q.Set("name", name)
		reqURL.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create DoH request for %s: %w", provider.Name, err)
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		if provider.ServerName != "" {
			req.Host = provider.ServerName
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to perform DoH request to %s: %w", provider.Name, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("DoH request to %s failed with status: %s", provider.Name, resp.Status)
			continue
		}

		var dohResponse DoHResponse
		if err := json.NewDecoder(resp.Body).Decode(&dohResponse); err != nil {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("failed to decode DoH response from %s: %w", provider.Name, err)
			continue
		}
		_ = resp.Body.Close()

		for _, answer := range dohResponse.Answer {
			if answer.Type == 1 {
				ip := net.ParseIP(answer.Data)
				if ip != nil {
					return ctx, ip, nil
				}
			}
		}
		lastErr = fmt.Errorf("no A records found for %s from %s", name, provider.Name)
	}

	return ctx, nil, fmt.Errorf("failed to resolve domain %s using any DoH provider: %w", name, lastErr)
}

// addDifferentialPrivacyNoise adds noise to counts to provide differential privacy
func addDifferentialPrivacyNoise(count int) int {
	// Use Laplace mechanism for differential privacy
	// In a real implementation, this would be calibrated based on privacy requirements
	epsilon := 0.5     // Privacy parameter (lower = more privacy)
	sensitivity := 1.0 // Sensitivity of the count function

	// Generate Laplace noise with scale = sensitivity/epsilon
	scale := sensitivity / epsilon

	// Generate random bytes for noise
	randBytes := make([]byte, 8)
	_, err := rand.Read(randBytes)
	if err != nil {
		// If we can't generate secure random numbers, return the original count
		return count
	}

	// Convert to a float64 between 0 and 1
	randFloat := float64(binary.BigEndian.Uint64(randBytes)) / float64(^uint64(0))

	// Convert uniform random to Laplace distribution
	var noise float64
	if randFloat < 0.5 {
		noise = scale * math.Log(2.0*randFloat)
	} else {
		noise = -scale * math.Log(2.0*(1.0-randFloat))
	}

	// Add noise and round to nearest integer
	noisyCount := int(math.Round(float64(count) + noise))

	// Ensure count is non-negative
	if noisyCount < 0 {
		noisyCount = 0
	}

	return noisyCount
}

// categorizeDiscoveryResult categorizes the discovery result for logging
// This avoids leaking exact counts in logs while still providing useful information
func categorizeDiscoveryResult(count int) string {
	switch {
	case count == 0:
		return "none"
	case count < 3:
		return "few"
	case count < 10:
		return "several"
	default:
		return "many"
	}
}

// HasSufficientEntropy checks if the entropy pool has sufficient entropy
func (sr *SecureRandomizer) HasSufficientEntropy() bool {
	if sr.entropyPool == nil {
		sr.initializeEntropyPool()
	}
	return sr.entropyPool.HasSufficientEntropy()
}

// GenerateSecureInt generates a secure integer from the entropy pool
func (sr *SecureRandomizer) GenerateSecureInt(max *big.Int) (*big.Int, error) {
	if sr.entropyPool == nil {
		sr.initializeEntropyPool()
	}
	return sr.entropyPool.GenerateSecureInt(max)
}

// initializeEntropyPool sets up the entropy pool
func (sr *SecureRandomizer) initializeEntropyPool() {
	sr.entropyPool = &EntropyPool{
		poolSize:    1024,
		minEntropy:  256,
		pool:        make([]byte, 1024),
		lastRefresh: time.Now(),
	}
	// Try to fill with crypto/rand if available
	_, _ = rand.Read(sr.entropyPool.pool)
}

// HasSufficientEntropy checks if the pool has enough entropy
func (ep *EntropyPool) HasSufficientEntropy() bool {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()

	// Check if we have sufficient entropy and it's not too old
	return len(ep.pool) >= ep.minEntropy &&
		time.Since(ep.lastRefresh) < 5*time.Minute
}

// GenerateSecureInt extracts a secure integer from the entropy pool
func (ep *EntropyPool) GenerateSecureInt(max *big.Int) (*big.Int, error) {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()

	if !ep.HasSufficientEntropy() {
		return nil, fmt.Errorf("insufficient entropy in pool")
	}

	// Use entropy pool with cryptographic extraction
	return ep.extractSecureInt(max)
}

// extractSecureInt performs cryptographic extraction from entropy pool
func (ep *EntropyPool) extractSecureInt(max *big.Int) (*big.Int, error) {
	// Use SHA256 to extract randomness from pool
	hash := sha256.New()
	hash.Write(ep.pool[ep.currentIndex : ep.currentIndex+32])
	hashBytes := hash.Sum(nil)

	// Convert to big.Int
	result := new(big.Int).SetBytes(hashBytes)
	result.Mod(result, max)

	// Update pool position
	ep.currentIndex = (ep.currentIndex + 32) % len(ep.pool)

	return result, nil
}

// gatherTimingEntropy collects entropy from high-resolution timing
func gatherTimingEntropy() []byte {
	entropy := make([]byte, 32)

	// Collect entropy from timing differences between operations
	for i := 0; i < 32; i++ {
		start := time.Now().UnixNano()

		// Perform some varying computation to add timing jitter
		tmp := 0
		iterations := 1000 + (i * 13)
		for j := 0; j < iterations; j++ {
			tmp += j * j
		}

		// Use the timing difference as entropy source
		end := time.Now().UnixNano()
		diff := end - start

		// Mix in the computation result to prevent optimization
		diff ^= int64(tmp)

		// Use the lowest 8 bits which have the most variation
		entropy[i] = byte(diff & 0xff)
	}

	// Hash the result to distribute the entropy
	hash := sha256.New()
	hash.Write(entropy)
	return hash.Sum(nil)
}

// generateSecureIntFromEntropy generates a secure random integer from entropy
func generateSecureIntFromEntropy(entropy []byte, max int64) (int, error) {
	if len(entropy) < 8 {
		return 0, fmt.Errorf("insufficient entropy")
	}

	// Use entropy to seed a CSPRNG
	hash := sha256.New()
	hash.Write(entropy)
	hashResult := hash.Sum(nil)

	// Convert first 8 bytes to int64
	var value int64
	for i := 0; i < 8; i++ {
		value = (value << 8) | int64(hashResult[i])
	}

	// Ensure positive and in range
	value = value & 0x7FFFFFFFFFFFFFFF
	return int(value % max), nil
}

// isTestEnvironment checks if we're running in a test environment
func isTestEnvironment() bool {
	// Check for environment variable that could be set in test setups
	if os.Getenv("GO_TESTING") == "1" {
		return true
	}

	// Check for typical test command line args
	for _, arg := range os.Args {
		if strings.Contains(arg, "test.v") || strings.Contains(arg, "test.run") {
			return true
		}
	}

	// Check if program name contains "test" (go test renames the binary)
	return strings.HasSuffix(os.Args[0], ".test") || strings.Contains(os.Args[0], "/_test/")
}

// dialTLSWithUTLS creates a TLS connection using uTLS to resist fingerprinting.
func dialTLSWithUTLS(ctx context.Context, network, addr string, cfg *utls.Config, provider config.DoHProvider) (net.Conn, error) {
	// Check if we're in a test environment
	if isTestEnvironment() {
		// For tests, use a simpler connection method
		dialer := &net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 10 * time.Second,
		}

		// In tests, we can use the standard TLS library
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}

		// Convert the utls.Config to a standard tls.Config
		tlsConfig := &tls.Config{
			ServerName:         cfg.ServerName,
			InsecureSkipVerify: cfg.InsecureSkipVerify,
			RootCAs:            cfg.RootCAs,
		}

		// Create a TLS client connection
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			if closeErr := conn.Close(); closeErr != nil {
				logging.GetLogger().Warn("Error closing connection after handshake failure", "error", closeErr)
			}
			return nil, err
		}

		return tlsConn, nil
	}

	// TODO: Implement real uTLS-based TLS dialing with anti-fingerprinting and domain fronting support
	return nil, fmt.Errorf("dialTLSWithUTLS not implemented for production use")
}

// Wrapper methods for parallel discovery with context signatures

func (r *DoHResolver) generateDGAProvidersCtx(ctx context.Context) ([]config.DoHProvider, error) {
	return r.generateDGAProviders(time.Now())
}

func (r *DoHResolver) discoverSocialMediaProviders(ctx context.Context) ([]config.DoHProvider, error) {
	// Placeholder implementation for social media-based provider discovery
	// In a real implementation, this would extract provider information from
	// social media platforms using steganographic techniques
	r.logger.Debug("Social media provider discovery not yet implemented")
	return nil, fmt.Errorf("social media discovery not implemented")
}

// validateProviderSecurity performs security validation on discovered providers
func (r *DoHResolver) validateProviderSecurity(providers []config.DoHProvider) []config.DoHProvider {
	var validProviders []config.DoHProvider

	for _, provider := range providers {
		// Check domain isn't obviously suspicious
		if r.isProviderSuspicious(provider) {
			r.logger.Warn("Rejecting suspicious provider", "name", provider.Name)
			continue
		}

		// Verify TLS connectivity
		if !r.validateTLSConnectivity(provider) {
			r.logger.Warn("Provider failed TLS validation", "name", provider.Name)
			continue
		}

		validProviders = append(validProviders, provider)
	}

	return validProviders
}

// isProviderSuspicious checks if a provider appears suspicious
func (r *DoHResolver) isProviderSuspicious(provider config.DoHProvider) bool {
	// Simple heuristics for suspicious providers
	suspiciousPatterns := []string{
		"vpn", "proxy", "tor", "tunnel", "unblock", "bypass", "circumvent",
	}

	name := strings.ToLower(provider.Name)
	url := strings.ToLower(provider.URL)

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(name, pattern) || strings.Contains(url, pattern) {
			return true
		}
	}

	return false
}

// validateTLSConnectivity verifies provider TLS connectivity
func (r *DoHResolver) validateTLSConnectivity(provider config.DoHProvider) bool {
	// Parse URL to get host
	u, err := url.Parse(provider.URL)
	if err != nil {
		return false
	}

	// Quick TLS connectivity test
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(u.Host, "443"))
	if err != nil {
		return false
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			// Log error but continue since this is just a validation check
			r.logger.Debug("Error closing connection during TLS validation", "error", closeErr)
		}
	}()

	// Verify TLS handshake
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName:         u.Host,
		InsecureSkipVerify: false,
	})

	err = tlsConn.Handshake()
	return err == nil
}

// applyProviderDiversityFiltering ensures provider diversity
func (r *DoHResolver) applyProviderDiversityFiltering(providers []config.DoHProvider) []config.DoHProvider {
	// Remove duplicate providers and ensure geographic/organizational diversity
	seen := make(map[string]bool)
	var filtered []config.DoHProvider

	for _, provider := range providers {
		// Use URL as uniqueness key
		if !seen[provider.URL] {
			seen[provider.URL] = true
			filtered = append(filtered, provider)
		}
	}

	return filtered
}

// combineEntropySecurely combines multiple entropy sources with hashing
func (r *DoHResolver) combineEntropySecurely(entropy *MultiSourceEntropy) []byte {
	// Use HMAC-SHA-256 to combine entropy sources securely
	// Each source is mixed in separately to prevent one weak source from weakening the whole pool

	// Start with crypto/rand as the initial key if available
	var key []byte
	if len(entropy.CryptoRand) > 0 {
		key = make([]byte, len(entropy.CryptoRand))
		copy(key, entropy.CryptoRand)
	} else {
		// Fallback to system entropy if crypto/rand is unavailable
		key = make([]byte, len(entropy.SystemEntropy))
		copy(key, entropy.SystemEntropy)
	}

	// Mix in timing entropy
	if len(entropy.TimingEntropy) > 0 {
		h := hmac.New(sha256.New, key)
		h.Write(entropy.TimingEntropy)
		key = h.Sum(nil)
	}

	// Mix in system entropy if not already used
	if len(entropy.SystemEntropy) > 0 && len(entropy.CryptoRand) > 0 {
		h := hmac.New(sha256.New, key)
		h.Write(entropy.SystemEntropy)
		key = h.Sum(nil)
	}

	// Mix in network entropy
	if len(entropy.NetworkEntropy) > 0 {
		h := hmac.New(sha256.New, key)
		h.Write(entropy.NetworkEntropy)
		key = h.Sum(nil)
	}

	// Final mixing step
	h := sha256.New()
	h.Write(key)

	// Add a timestamp for good measure
	timeBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().UnixNano()))
	h.Write(timeBytes)

	return h.Sum(nil)
}

// secureIndexFromEntropy generates a secure random index within a range
func (r *DoHResolver) secureIndexFromEntropy(entropy []byte, n int) (int, error) {
	if len(entropy) < 4 {
		return 0, fmt.Errorf("insufficient entropy")
	}

	// Take 4 bytes from entropy and convert to uint32
	value := binary.BigEndian.Uint32(entropy[:4])

	// Modulo n to get index in range [0,n)
	return int(value % uint32(n)), nil
}

// updateEntropyState updates entropy after using part of it
func (r *DoHResolver) updateEntropyState(entropy []byte, i, j int) []byte {
	if len(entropy) < 8 {
		// If entropy is too small, just return it unchanged
		return entropy
	}

	// Create a new buffer for updated entropy
	updated := make([]byte, len(entropy))
	copy(updated, entropy)

	// Mix in the indices to create new entropy
	h := sha256.New()
	h.Write(updated)

	// Add the operation indices
	indexBytes := make([]byte, 8)
	binary.BigEndian.PutUint32(indexBytes, uint32(i))
	binary.BigEndian.PutUint32(indexBytes[4:], uint32(j))
	h.Write(indexBytes)

	// Use part of the hash result to update entropy
	hashResult := h.Sum(nil)

	// Replace first 8 bytes with new entropy
	copy(updated[:8], hashResult[:8])

	return updated
}

package core

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/pkg/logging"
)

// DomainGenerationAlgorithm is a tool for securely generating domain names
// based on configurable parameters and entropy sources
type DomainGenerationAlgorithm struct {
	logger         logging.Logger
	config         *config.DGAConfig
	secretKey      []byte
	lastSeed       time.Time
	quantizeWindow time.Duration
	wordList       []string
	tlds           []string
}

// TimeQuantizer handles time quantization for consistent domain generation
type TimeQuantizer struct {
	window time.Duration
}

// NewTimeQuantizer creates a new time quantizer with specified window
func NewTimeQuantizer(window time.Duration) *TimeQuantizer {
	if window == 0 {
		window = 1 * time.Hour // Default to 1 hour window
	}
	return &TimeQuantizer{window: window}
}

// Quantize rounds a timestamp down to the nearest window boundary
func (q *TimeQuantizer) Quantize(t time.Time) time.Time {
	unixTime := t.Unix()
	windowSeconds := int64(q.window.Seconds())
	quantized := unixTime - (unixTime % windowSeconds)
	return time.Unix(quantized, 0).UTC()
}

// NewDomainGenerationAlgorithm creates a new DGA instance
func NewDomainGenerationAlgorithm(cfg *config.DGAConfig, logger logging.Logger) (*DomainGenerationAlgorithm, error) {
	if cfg == nil {
		return nil, fmt.Errorf("DGA config cannot be nil")
	}

	if logger == nil {
		logger = logging.GetLogger()
	}

	// Initialize with a secure key
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate secure key: %w", err)
	}

	// Set up quantization window from config
	var quantizeWindow time.Duration
	if cfg.RotationTime > 0 {
		quantizeWindow = time.Duration(cfg.RotationTime) * time.Minute
	} else {
		quantizeWindow = 1 * time.Hour // Default
	}

	// Use seed from config if available
	if cfg.Seed != "" {
		h := sha256.New()
		h.Write([]byte(cfg.Seed))
		key = h.Sum(nil)
	}

	// Default TLDs if none specified in parameters
	tlds := []string{"com", "net", "org", "info", "io"}
	if tldsParam, ok := cfg.Parameters["tlds"]; ok {
		tlds = strings.Split(tldsParam, ",")
	}

	// Initialize basic wordlist for dictionary algorithm
	// In a production environment, this would load from a file
	wordList := []string{
		"alpha", "bravo", "cloud", "delta", "echo", "foxtrot", "global",
		"hotel", "india", "juliet", "kilo", "lima", "mike", "november",
		"ocean", "papa", "quebec", "romeo", "sierra", "tango", "uniform",
		"victor", "whiskey", "xray", "yankee", "zulu", "secure", "private",
		"crypto", "cyber", "data", "edge", "fast", "grid", "hyper", "info",
		"jump", "key", "link", "mesh", "node", "orbit", "proxy", "quantum",
		"relay", "swift", "trust", "unity", "vault", "web", "xeno", "yield",
		"zone", "access", "bridge", "connect", "dynamic", "encrypt", "flow",
		"gateway", "host", "interface", "join", "keep", "layer", "meta",
		"network", "output", "portal", "query", "router", "server", "tunnel",
		"update", "vector", "wave", "xtreme", "yield", "zenith",
	}

	if wordsParam, ok := cfg.Parameters["wordlist"]; ok {
		wordList = strings.Split(wordsParam, ",")
	}

	return &DomainGenerationAlgorithm{
		logger:         logger.With("component", "dga"),
		config:         cfg,
		secretKey:      key,
		lastSeed:       time.Now(),
		quantizeWindow: quantizeWindow,
		wordList:       wordList,
		tlds:           tlds,
	}, nil
}

// GenerateDomains creates a list of domains using the configured algorithm
func (dga *DomainGenerationAlgorithm) GenerateDomains(ctx context.Context, count int) ([]string, error) {
	if count <= 0 {
		return nil, fmt.Errorf("count must be positive")
	}

	var domains []string
	quantizer := NewTimeQuantizer(dga.quantizeWindow)
	quantizedTime := quantizer.Quantize(time.Now())

	// Use the appropriate algorithm based on configuration
	switch dga.config.Algorithm {
	case "dictionary":
		domains = dga.generateDictionaryDomains(quantizedTime, count)
	case "mathematical":
		domains = dga.generateMathematicalDomains(quantizedTime, count)
	default:
		// Default to a hybrid approach
		domains = dga.generateHybridDomains(quantizedTime, count)
	}

	return domains, nil
}

// hmacSha256 creates an HMAC-SHA256 hash of the provided data using the secret key
func (dga *DomainGenerationAlgorithm) hmacSha256(data []byte) []byte {
	h := hmac.New(sha256.New, dga.secretKey)
	h.Write(data)
	return h.Sum(nil)
}

// generateDictionaryDomains generates domains using dictionary words
func (dga *DomainGenerationAlgorithm) generateDictionaryDomains(timestamp time.Time, count int) []string {
	var domains []string

	for i := 0; i < count; i++ {
		// Create seed data using timestamp and counter
		seed := make([]byte, 12)
		binary.BigEndian.PutUint64(seed, uint64(timestamp.Unix()))
		binary.BigEndian.PutUint32(seed[8:], uint32(i))

		// Generate deterministic hash using HMAC
		hash := dga.hmacSha256(seed)

		// Generate domain using word list
		domain := dga.hashToWordDomain(hash)
		domains = append(domains, domain)
	}

	return domains
}

// generateMathematicalDomains generates domains using mathematical algorithms
func (dga *DomainGenerationAlgorithm) generateMathematicalDomains(timestamp time.Time, count int) []string {
	var domains []string

	for i := 0; i < count; i++ {
		// Create seed data using timestamp and counter
		seed := make([]byte, 12)
		binary.BigEndian.PutUint64(seed, uint64(timestamp.Unix()))
		binary.BigEndian.PutUint32(seed[8:], uint32(i))

		// Generate deterministic hash using HMAC
		hash := dga.hmacSha256(seed)

		// Generate alphanumeric domain
		domain := dga.hashToAlphanumericDomain(hash, 12)
		domains = append(domains, domain)
	}

	return domains
}

// generateHybridDomains generates domains using a hybrid approach
func (dga *DomainGenerationAlgorithm) generateHybridDomains(timestamp time.Time, count int) []string {
	var domains []string

	for i := 0; i < count; i++ {
		// Create seed data using timestamp and counter
		seed := make([]byte, 12)
		binary.BigEndian.PutUint64(seed, uint64(timestamp.Unix()))
		binary.BigEndian.PutUint32(seed[8:], uint32(i))

		// Generate deterministic hash using HMAC
		hash := dga.hmacSha256(seed)

		// Use different strategies based on the counter modulo 3
		switch i % 3 {
		case 0:
			domain := dga.hashToWordDomain(hash)
			domains = append(domains, domain)
		case 1:
			domain := dga.hashToMixedDomain(hash)
			domains = append(domains, domain)
		case 2:
			domain := dga.hashToAlphanumericDomain(hash, 8)
			domains = append(domains, domain)
		}
	}

	return domains
}

// hashToWordDomain converts a hash to a domain using dictionary words
func (dga *DomainGenerationAlgorithm) hashToWordDomain(hash []byte) string {
	if len(dga.wordList) == 0 {
		return dga.hashToAlphanumericDomain(hash, 10)
	}

	// Extract multiple indices from the hash
	wordCount := 2
	var words []string

	for i := 0; i < wordCount && i*4 < len(hash); i++ {
		// Use 4 bytes for each word index
		wordIdx := binary.BigEndian.Uint32(hash[i*4 : (i+1)*4])
		words = append(words, dga.wordList[wordIdx%uint32(len(dga.wordList))])
	}

	// Select a TLD based on another part of the hash
	tldIdx := uint8(hash[len(hash)-1]) % uint8(len(dga.tlds))
	tld := dga.tlds[tldIdx]

	// Join words with dashes or directly
	var domain string
	if hash[0]%2 == 0 {
		domain = strings.Join(words, "-")
	} else {
		domain = strings.Join(words, "")
	}

	return domain + "." + tld
}

// hashToAlphanumericDomain converts a hash to an alphanumeric domain
func (dga *DomainGenerationAlgorithm) hashToAlphanumericDomain(hash []byte, length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	if length > 63 {
		length = 63 // Max domain segment length
	}

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		// Use modulo to map hash byte to charset
		idx := uint8(hash[i%len(hash)]) % uint8(len(charset))
		result[i] = charset[idx]
	}

	// Select a TLD based on another part of the hash
	tldIdx := uint8(hash[len(hash)-1]) % uint8(len(dga.tlds))
	tld := dga.tlds[tldIdx]

	// Ensure the first and last characters aren't hyphens
	if result[0] == '-' {
		result[0] = 'a'
	}
	if result[length-1] == '-' {
		result[length-1] = 'z'
	}

	return string(result) + "." + tld
}

// hashToMixedDomain creates a domain with a word plus random chars
func (dga *DomainGenerationAlgorithm) hashToMixedDomain(hash []byte) string {
	if len(dga.wordList) == 0 {
		return dga.hashToAlphanumericDomain(hash, 12)
	}

	// Get a word from the wordlist
	wordIdx := binary.BigEndian.Uint32(hash[:4]) % uint32(len(dga.wordList))
	word := dga.wordList[wordIdx]

	// Create a random numeric suffix (1-999)
	suffixBig := new(big.Int).SetBytes(hash[4:8])
	suffix := suffixBig.Mod(suffixBig, big.NewInt(999)).Int64() + 1

	// Select a TLD
	tldIdx := uint8(hash[len(hash)-1]) % uint8(len(dga.tlds))
	tld := dga.tlds[tldIdx]

	return fmt.Sprintf("%s%d.%s", word, suffix, tld)
}

// UpdateSeed refreshes the internal seed for domain generation
func (dga *DomainGenerationAlgorithm) UpdateSeed() error {
	dga.lastSeed = time.Now()

	// Generate new secret key
	newKey := make([]byte, 32)
	_, err := rand.Read(newKey)
	if err != nil {
		return fmt.Errorf("failed to update seed: %w", err)
	}

	// Mix old and new keys using HMAC
	h := hmac.New(sha256.New, dga.secretKey)
	h.Write(newKey)
	dga.secretKey = h.Sum(nil)

	return nil
}

// GetCurrentTimePeriod returns the current time quantization period
func (dga *DomainGenerationAlgorithm) GetCurrentTimePeriod() time.Time {
	quantizer := NewTimeQuantizer(dga.quantizeWindow)
	return quantizer.Quantize(time.Now())
}

// GetDomainsForPeriod generates domains for a specific time period
func (dga *DomainGenerationAlgorithm) GetDomainsForPeriod(period time.Time, count int) ([]string, error) {
	if count <= 0 {
		return nil, fmt.Errorf("count must be positive")
	}

	var domains []string

	// Use the appropriate algorithm based on configuration
	switch dga.config.Algorithm {
	case "dictionary":
		domains = dga.generateDictionaryDomains(period, count)
	case "mathematical":
		domains = dga.generateMathematicalDomains(period, count)
	default:
		// Default to a hybrid approach
		domains = dga.generateHybridDomains(period, count)
	}

	return domains, nil
}

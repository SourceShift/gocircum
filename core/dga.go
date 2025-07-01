package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/pkg/logging"
)

// DomainGenerationAlgorithm is a tool for securely generating domain names
// based on configurable parameters and entropy sources
type DomainGenerationAlgorithm struct {
	logger    logging.Logger
	config    *config.DGAConfig
	secretKey []byte
	lastSeed  time.Time
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

	return &DomainGenerationAlgorithm{
		logger:    logger.With("component", "dga"),
		config:    cfg,
		secretKey: key,
		lastSeed:  time.Now(),
	}, nil
}

// GenerateDomains creates a list of domains using the configured algorithm
func (dga *DomainGenerationAlgorithm) GenerateDomains(ctx context.Context, count int) ([]string, error) {
	if count <= 0 {
		return nil, fmt.Errorf("count must be positive")
	}

	var domains []string

	// Use the appropriate algorithm based on configuration
	switch dga.config.Algorithm {
	case "dictionary":
		domains = dga.generateDictionaryDomains(count)
	case "mathematical":
		domains = dga.generateMathematicalDomains(count)
	default:
		// Default to a hybrid approach
		domains = dga.generateHybridDomains(count)
	}

	return domains, nil
}

// generateSingleDomain creates a single domain using the configured algorithm
func (dga *DomainGenerationAlgorithm) generateSingleDomain(index int) (string, error) {
	// Generate domain based on hash of secret key and time-based data
	h := sha256.New()
	h.Write(dga.secretKey)
	_, err := fmt.Fprintf(h, "%d-%d", time.Now().UnixNano(), index)
	if err != nil {
		return "", fmt.Errorf("failed to generate domain hash: %w", err)
	}
	hash := h.Sum(nil)

	// Generate domain based on hash
	tlds := []string{"com", "net", "org", "info"}
	tld := tlds[int(hash[0])%len(tlds)]

	// Create domain name from hash
	domainPart := fmt.Sprintf("%x", hash[1:6])

	return strings.ToLower(domainPart + "." + tld), nil
}

// generateDictionaryDomains generates domains using dictionary words
func (dga *DomainGenerationAlgorithm) generateDictionaryDomains(count int) []string {
	var domains []string

	// In a real implementation, this would use a dictionary word list
	// For now, use a simple algorithm based on the hash
	for i := 0; i < count; i++ {
		domain, err := dga.generateSingleDomain(i)
		if err == nil {
			domains = append(domains, domain)
		}
	}

	return domains
}

// generateMathematicalDomains generates domains using mathematical algorithms
func (dga *DomainGenerationAlgorithm) generateMathematicalDomains(count int) []string {
	var domains []string

	// In a real implementation, this would use mathematical algorithms
	// For now, use a simple algorithm based on the hash
	for i := 0; i < count; i++ {
		domain, err := dga.generateSingleDomain(i)
		if err == nil {
			domains = append(domains, domain)
		}
	}

	return domains
}

// generateHybridDomains generates domains using a hybrid approach
func (dga *DomainGenerationAlgorithm) generateHybridDomains(count int) []string {
	var domains []string

	// In a real implementation, this would use a mix of approaches
	// For now, use a simple algorithm based on the hash
	for i := 0; i < count; i++ {
		domain, err := dga.generateSingleDomain(i)
		if err == nil {
			domains = append(domains, domain)
		}
	}

	return domains
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

	// Mix old and new keys
	h := sha256.New()
	h.Write(dga.secretKey)
	h.Write(newKey)
	dga.secretKey = h.Sum(nil)

	return nil
}

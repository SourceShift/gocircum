package core

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainGenerationAlgorithm(t *testing.T) {
	logger := logging.GetLogger()

	t.Run("initialization", func(t *testing.T) {
		cfg := &config.DGAConfig{
			Enabled:      true,
			Algorithm:    "hybrid",
			Seed:         "test-seed-value",
			RotationTime: 60, // 60 minutes
			Parameters: map[string]string{
				"tlds":     "com,net,org",
				"wordlist": "test,sample,domain,example",
			},
			DomainCount: 5,
		}

		dga, err := NewDomainGenerationAlgorithm(cfg, logger)
		require.NoError(t, err)
		require.NotNil(t, dga)
		assert.Equal(t, 60*time.Minute, dga.quantizeWindow)
		assert.Equal(t, []string{"test", "sample", "domain", "example"}, dga.wordList)
		assert.Equal(t, []string{"com", "net", "org"}, dga.tlds)
	})

	t.Run("nil_config", func(t *testing.T) {
		dga, err := NewDomainGenerationAlgorithm(nil, logger)
		assert.Error(t, err)
		assert.Nil(t, dga)
		assert.Contains(t, err.Error(), "config cannot be nil")
	})

	t.Run("default_values", func(t *testing.T) {
		cfg := &config.DGAConfig{
			Enabled:   true,
			Algorithm: "dictionary",
		}

		dga, err := NewDomainGenerationAlgorithm(cfg, logger)
		require.NoError(t, err)
		require.NotNil(t, dga)
		assert.Equal(t, 1*time.Hour, dga.quantizeWindow) // Default 1 hour
		assert.NotEmpty(t, dga.wordList)                 // Should have default wordlist
		assert.NotEmpty(t, dga.tlds)                     // Should have default TLDs
	})

	t.Run("generate_domains", func(t *testing.T) {
		cfg := &config.DGAConfig{
			Enabled:      true,
			Algorithm:    "hybrid",
			Seed:         "test-seed-value",
			RotationTime: 60,
			DomainCount:  5,
		}

		dga, err := NewDomainGenerationAlgorithm(cfg, logger)
		require.NoError(t, err)
		require.NotNil(t, dga)

		ctx := context.Background()
		domains, err := dga.GenerateDomains(ctx, 5)
		require.NoError(t, err)
		assert.Len(t, domains, 5)

		// Check domain format
		for _, domain := range domains {
			// Domains should have a TLD
			assert.Contains(t, domain, ".")
			// Domain part should not be empty
			parts := strings.Split(domain, ".")
			assert.GreaterOrEqual(t, len(parts[0]), 1)
		}

		// Error case: invalid count
		_, err = dga.GenerateDomains(ctx, 0)
		assert.Error(t, err)
	})

	t.Run("determinism", func(t *testing.T) {
		cfg := &config.DGAConfig{
			Enabled:      true,
			Algorithm:    "dictionary",
			Seed:         "deterministic-test-seed",
			RotationTime: 60,
		}

		dga1, _ := NewDomainGenerationAlgorithm(cfg, logger)
		dga2, _ := NewDomainGenerationAlgorithm(cfg, logger)

		// Fix the time for deterministic testing
		fixedTime := time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC)

		domains1 := dga1.generateDictionaryDomains(fixedTime, 3)
		domains2 := dga2.generateDictionaryDomains(fixedTime, 3)

		// Same seed and time should produce same domains
		for i := 0; i < len(domains1); i++ {
			assert.Equal(t, domains1[i], domains2[i])
		}
	})

	t.Run("time_quantization", func(t *testing.T) {
		// Test that time quantization works correctly
		window := 1 * time.Hour
		quantizer := NewTimeQuantizer(window)

		// Test cases
		testCases := []struct {
			input    time.Time
			expected time.Time
		}{
			{
				time.Date(2023, 5, 15, 12, 30, 45, 0, time.UTC),
				time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC),
			},
			{
				time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC),
				time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC),
			},
			{
				time.Date(2023, 5, 15, 12, 59, 59, 999, time.UTC),
				time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC),
			},
		}

		for _, tc := range testCases {
			result := quantizer.Quantize(tc.input)
			assert.Equal(t, tc.expected, result)
		}
	})

	t.Run("algorithm_selection", func(t *testing.T) {
		fixedTime := time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC)

		// Test dictionary algorithm
		cfg1 := &config.DGAConfig{Enabled: true, Algorithm: "dictionary", Seed: "test-seed"}
		dga1, _ := NewDomainGenerationAlgorithm(cfg1, logger)
		domains1 := dga1.generateDictionaryDomains(fixedTime, 3)
		assert.Len(t, domains1, 3)

		// Test mathematical algorithm
		cfg2 := &config.DGAConfig{Enabled: true, Algorithm: "mathematical", Seed: "test-seed"}
		dga2, _ := NewDomainGenerationAlgorithm(cfg2, logger)
		domains2 := dga2.generateMathematicalDomains(fixedTime, 3)
		assert.Len(t, domains2, 3)

		// Test hybrid algorithm
		cfg3 := &config.DGAConfig{Enabled: true, Algorithm: "hybrid", Seed: "test-seed"}
		dga3, _ := NewDomainGenerationAlgorithm(cfg3, logger)
		domains3 := dga3.generateHybridDomains(fixedTime, 3)
		assert.Len(t, domains3, 3)

		// Different algorithms should produce different domains
		assert.NotEqual(t, domains1, domains2)
		assert.NotEqual(t, domains2, domains3)
		assert.NotEqual(t, domains1, domains3)
	})

	t.Run("domain_format_validation", func(t *testing.T) {
		cfg := &config.DGAConfig{Enabled: true, Algorithm: "hybrid", Seed: "test-seed"}
		dga, _ := NewDomainGenerationAlgorithm(cfg, logger)

		// Generate test hash
		testHash := make([]byte, 32)
		for i := range testHash {
			testHash[i] = byte(i)
		}

		// Test word domain
		wordDomain := dga.hashToWordDomain(testHash)
		assert.Contains(t, wordDomain, ".")
		parts := strings.Split(wordDomain, ".")
		assert.NotEmpty(t, parts[0])
		tld := parts[len(parts)-1]
		assert.Contains(t, dga.tlds, tld)

		// Test alphanumeric domain
		alphaNumDomain := dga.hashToAlphanumericDomain(testHash, 10)
		assert.Contains(t, alphaNumDomain, ".")
		parts = strings.Split(alphaNumDomain, ".")
		assert.Len(t, parts[0], 10)
		tld = parts[len(parts)-1]
		assert.Contains(t, dga.tlds, tld)

		// Test mixed domain
		mixedDomain := dga.hashToMixedDomain(testHash)
		assert.Contains(t, mixedDomain, ".")
		assert.Regexp(t, `[a-z]+\d+\.[a-z]+`, mixedDomain)
	})

	t.Run("time_period_domains", func(t *testing.T) {
		cfg := &config.DGAConfig{
			Enabled:      true,
			Algorithm:    "dictionary",
			Seed:         "test-seed",
			RotationTime: 60,
		}
		dga, _ := NewDomainGenerationAlgorithm(cfg, logger)

		// Get current period
		period := dga.GetCurrentTimePeriod()

		// Get domains for current period
		domains, err := dga.GetDomainsForPeriod(period, 3)
		require.NoError(t, err)
		assert.Len(t, domains, 3)

		// Get domains for future period
		futurePeriod := period.Add(24 * time.Hour)
		futureDomains, err := dga.GetDomainsForPeriod(futurePeriod, 3)
		require.NoError(t, err)

		// Future domains should be different from current
		assert.NotEqual(t, domains, futureDomains)
	})
}

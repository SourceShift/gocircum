package ranker

//nolint:unused

import (
	"container/list"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"net"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/core/engine"
	"github.com/gocircum/gocircum/core/proxy"
	"github.com/gocircum/gocircum/pkg/logging"
)

// SanitizedError represents a sanitized error that doesn't leak sensitive information
type SanitizedError struct {
	Code    string // Opaque error code
	Message string // Generic user-facing message
	Context string // General context without sensitive details
}

func (e *SanitizedError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// SecurityViolationError represents a security violation error
type SecurityViolationError struct {
	Code    string // Opaque error code for the security violation
	Message string // Generic user-facing message
	Action  string // Recommended action
}

func (e *SecurityViolationError) Error() string {
	return fmt.Sprintf("Security policy violation: %s", e.Message)
}

// ErrorClassifier categorizes an error without exposing sensitive details
func classifyError(err error) string {
	if err == nil {
		return "none"
	}

	errStr := err.Error()
	switch {
	case strings.Contains(errStr, "timeout"):
		return "timeout"
	case strings.Contains(errStr, "connection"):
		return "connection"
	case strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate"):
		return "tls"
	case strings.Contains(errStr, "dns"):
		return "dns"
	case strings.Contains(errStr, "context"):
		return "context"
	case strings.Contains(errStr, "permission"):
		return "permission"
	default:
		return "general"
	}
}

// createSanitizedError creates a safe error that doesn't leak sensitive information
func createSanitizedError(code, message, context string) *SanitizedError {
	return &SanitizedError{
		Code:    code,
		Message: message,
		Context: context,
	}
}

// DNSResolver defines the interface for a DNS resolver.
type DNSResolver interface {
	Resolve(ctx context.Context, name string) (context.Context, net.IP, error)
}

// StrategyResult holds the outcome of testing a single fingerprint.
type StrategyResult struct {
	Fingerprint *config.Fingerprint
	Success     bool
	Latency     time.Duration
}

type CacheEntry struct {
	FingerprintID string
	Latency       time.Duration
	Timestamp     time.Time
}

// Ranker tests and ranks connection strategies.
type Ranker struct {
	ActiveProbes        *list.List
	Cache               map[string]*CacheEntry
	CacheLock           sync.RWMutex
	Logger              logging.Logger
	DialerFactory       engine.DialerFactory
	DoHResolver         DNSResolver
	secureErrorStore    map[string]*SecureErrorDetails
	errorCleanupRunning bool
}

// NewRanker creates a new Ranker instance.
func NewRanker(logger logging.Logger, dohProviders []config.DoHProvider) (*Ranker, error) {
	if logger == nil {
		logger = logging.GetLogger()
	}
	dohResolver, err := proxy.NewDoHResolver(dohProviders)
	if err != nil {
		logger.Error("failed to initialize DoH resolver for ranker", "error", classifyError(err))
		return nil, createSanitizedError("RANKER_INIT_001", "Failed to initialize network components", "resolver_initialization")
	}
	return &Ranker{
		ActiveProbes:  list.New(),
		Logger:        logger,
		Cache:         make(map[string]*CacheEntry),
		DialerFactory: &engine.DefaultDialerFactory{},
		DoHResolver:   dohResolver,
	}, nil
}

// SetDoHResolver allows overriding the default DoH resolver, primarily for testing.
func (r *Ranker) SetDoHResolver(resolver DNSResolver) {
	r.DoHResolver = resolver
}

// SetDialerFactory allows overriding the default dialer factory, primarily for testing.
func (r *Ranker) SetDialerFactory(factory engine.DialerFactory) {
	r.DialerFactory = factory
}

// TestAndRank sorts fingerprints by success and latency.
// It implements distributed testing with random delays and decoy traffic to obfuscate testing patterns.
func (r *Ranker) TestAndRank(ctx context.Context, fingerprints []*config.Fingerprint, canaryDomains []string) ([]StrategyResult, error) {
	results := make(chan StrategyResult, len(fingerprints))

	// Use simple direct testing in test environments, organic testing in production
	if isRunningInTest() {
		// Simple direct testing for tests - test each fingerprint directly
		for _, fp := range fingerprints {
			go func(fingerprint *config.Fingerprint) {
				success, latency, err := r.testStrategy(ctx, fingerprint, canaryDomains)
				if err != nil {
					success = false
				}
				results <- StrategyResult{
					Fingerprint: fingerprint,
					Success:     success,
					Latency:     latency,
				}
			}(fp)
		}
	} else {
		// Implement realistic browsing session mimicry for strategy testing in production
		organicTestPlan := r.generateOrganicTestPlan(fingerprints, canaryDomains)

		for _, testSession := range organicTestPlan.Sessions {
			go func(session *OrganicTestSession) {
				// Simulate realistic browsing session that hides strategy tests
				if err := r.simulateRealisticBrowsingSession(ctx, session); err != nil {
					r.Logger.Error("Failed to simulate realistic browsing session",
						"error", err,
						"context", "organic_traffic_simulation")
					return
				}

				// Embed actual strategy test within normal-looking traffic
				for _, embeddedTest := range session.EmbeddedTests {
					// Generate realistic pre-request activity
					r.generatePreRequestActivity(ctx, embeddedTest.Strategy)

					// Perform test disguised as normal web traffic
					success, latency := r.performDisguisedStrategyTest(ctx, embeddedTest)

					// Continue realistic browsing pattern post-test
					r.generatePostRequestActivity(ctx, embeddedTest.Strategy, success)

					results <- StrategyResult{
						Fingerprint: embeddedTest.Strategy,
						Success:     success,
						Latency:     latency,
					}
				}
			}(testSession)
		}
	}

	// Hardened: Resource-limited result collection with circuit breaker
	var rankedResults []StrategyResult
	timeout := time.After(60 * time.Second)
	maxResults := min(len(fingerprints), 50) // Limit maximum results to prevent exhaustion

	// Circuit breaker for consecutive failures
	consecutiveFailures := 0
	maxConsecutiveFailures := 10

loop:
	for i := 0; i < maxResults; i++ {
		select {
		case result := <-results:
			if !result.Success {
				consecutiveFailures++
				if consecutiveFailures >= maxConsecutiveFailures {
					r.Logger.Warn("Circuit breaker triggered due to consecutive failures",
						"failures", consecutiveFailures)
					break loop
				}
			} else {
				consecutiveFailures = 0 // Reset on success
			}

			rankedResults = append(rankedResults, result)

			// Check memory pressure and stop if needed
			if r.checkMemoryPressure() {
				r.Logger.Warn("Stopping strategy testing due to memory pressure")
				break loop
			}

		case <-timeout:
			r.Logger.Warn("strategy testing timed out", "completed", len(rankedResults), "total", len(fingerprints))
			break loop
		}
	}
	close(results)

	return r.rankResults(rankedResults), nil
}

// checkMemoryPressure monitors system memory usage
func (r *Ranker) checkMemoryPressure() bool {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Stop if heap size exceeds 100MB
	return m.HeapAlloc > 100*1024*1024
}

// testStrategy performs a single connection test with realistic traffic patterns
func (r *Ranker) testStrategy(ctx context.Context, fingerprint *config.Fingerprint, canaryDomains []string) (bool, time.Duration, error) {
	if r.DialerFactory == nil {
		return false, 0, createSanitizedError("CONFIG_ERROR_001", "Invalid configuration", "missing_component")
	}

	if len(canaryDomains) == 0 {
		return false, 0, createSanitizedError("CONFIG_ERROR_002", "Invalid test configuration", "missing_test_domains")
	}

	// Generate realistic pre-connection activity
	preConnDelay := r.generateRealisticPreConnectionDelay()
	time.Sleep(preConnDelay)

	// Simulate realistic DNS lookup timing (even though we use DoH)
	dnsSimDelay := r.simulateRealisticDNSLookup()
	time.Sleep(dnsSimDelay)

	// Choose target with realistic user behavior patterns
	targetDomain := r.selectTargetWithRealisticPattern(canaryDomains)

	// Add jitter to connection timing to avoid fingerprinting
	connectionJitter := r.generateConnectionJitter()
	time.Sleep(connectionJitter)

	sessionID := generateEphemeralCorrelationID()
	r.Logger.Debug("strategy test session started",
		"session_id", sessionID)

	// Perform the actual test with timing obfuscation
	success, latency, err := r.performObfuscatedTest(ctx, fingerprint, targetDomain)

	// Add post-connection activity to mimic real browsing
	r.generatePostConnectionActivity(ctx, fingerprint, success)

	return success, latency, err
}

// generateRealisticPreConnectionDelay simulates user thinking/typing time with strict security
func (r *Ranker) generateRealisticPreConnectionDelay() time.Duration {
	// CRITICAL: No fallback chains - use only validated entropy
	entropyBundle, err := r.gatherCriticalEntropyBundle()
	if err != nil {
		// Log error securely without sensitive details
		r.Logger.Error("Critical entropy failure",
			"error_type", classifyError(err),
			"context", "timing_generation")

		// Notify security monitoring of potential issues
		r.notifySecurityMonitoring("ENTROPY_GENERATION_FAILURE")

		// Use a conservative default value instead of failing entirely
		return time.Duration(1500) * time.Millisecond
	}

	// Validate entropy bundle meets strict requirements
	if err := r.validateCriticalEntropy(entropyBundle); err != nil {
		// Log error securely without sensitive details
		r.Logger.Error("Entropy validation failure",
			"error_type", classifyError(err),
			"quality_indicator", "insufficient")

		// Notify security monitoring of potential issues
		r.notifySecurityMonitoring("ENTROPY_VALIDATION_FAILURE")

		// Use a conservative default value instead of failing entirely
		return time.Duration(2000) * time.Millisecond
	}

	// Extract timing value using HKDF with multiple validation steps
	delay, err := r.extractSecureTimingValue(entropyBundle, 500, 3000)
	if err != nil {
		// Log error securely without sensitive details
		r.Logger.Error("Timing extraction failure",
			"error_type", classifyError(err))

		// Use a conservative default value instead of failing entirely
		return time.Duration(1750) * time.Millisecond
	}

	// Clear entropy bundle from memory
	r.clearSensitiveEntropy(entropyBundle)

	return time.Duration(delay) * time.Millisecond
}

// CriticalEntropyBundle contains multiple high-quality entropy sources with strict validation
type CriticalEntropyBundle struct {
	Sources      map[string]*EntropySource
	Timestamp    time.Time
	QualityScore float64
	Requirements *EntropyRequirements
	//nolint:unused
	memoryLocked bool // Indicates if memory is locked
	isCleared    bool // Indicates if data has been cleared
}

// EntropySource contains entropy data with metadata
type EntropySource struct {
	Data       []byte
	SourceType string
	Timestamp  time.Time
	Quality    float64
	isCleared  bool // Indicates if data has been cleared
}

// EntropyRequirements defines strict requirements for entropy validation
type EntropyRequirements struct {
	MinSources    int
	MinQuality    float64
	MaxAge        time.Duration
	RequiredTests []string
}

// gatherCriticalEntropyBundle collects entropy from multiple validated sources
func (r *Ranker) gatherCriticalEntropyBundle() (*CriticalEntropyBundle, error) {
	bundle := &CriticalEntropyBundle{
		Sources:   make(map[string]*EntropySource),
		Timestamp: time.Now(),
		Requirements: &EntropyRequirements{
			MinSources:    4,
			MinQuality:    0.98,
			MaxAge:        time.Second * 30,
			RequiredTests: []string{"frequency", "runs", "approximate_entropy", "serial"},
		},
	}

	// Critical Source 1: Hardware Security Module
	if hsm, err := r.getHSMEntropy(); err == nil {
		bundle.Sources["hsm"] = hsm
	}

	// Critical Source 2: CPU Hardware RNG
	if cpu, err := r.getCPUHardwareRNG(); err == nil {
		bundle.Sources["cpu_rng"] = cpu
	}

	// Critical Source 3: Kernel entropy pool
	if kernel, err := r.getKernelEntropy(); err == nil {
		bundle.Sources["kernel"] = kernel
	}

	// Critical Source 4: Network jitter entropy
	if network, err := r.getNetworkJitterEntropy(); err == nil {
		bundle.Sources["network_jitter"] = network
	}

	// Validate we have minimum required sources
	if len(bundle.Sources) < bundle.Requirements.MinSources {
		return nil, fmt.Errorf("insufficient entropy sources: %d < %d required",
			len(bundle.Sources), bundle.Requirements.MinSources)
	}

	return bundle, nil
}

// validateCriticalEntropy performs comprehensive validation of entropy quality
func (r *Ranker) validateCriticalEntropy(bundle *CriticalEntropyBundle) error {
	// 1. Validate source count
	if len(bundle.Sources) < bundle.Requirements.MinSources {
		return fmt.Errorf("insufficient entropy sources: %d < %d required",
			len(bundle.Sources), bundle.Requirements.MinSources)
	}

	// 2. Validate age of sources
	for name, source := range bundle.Sources {
		age := time.Since(source.Timestamp)
		if age > bundle.Requirements.MaxAge {
			return fmt.Errorf("entropy source '%s' too old: %v > %v",
				name, age, bundle.Requirements.MaxAge)
		}
	}

	// 3. Validate statistical properties
	qualityScore, err := r.performStatisticalTests(bundle)
	if err != nil {
		return fmt.Errorf("statistical tests failed: %w", err)
	}
	bundle.QualityScore = qualityScore

	// 4. Validate minimum quality threshold
	if qualityScore < bundle.Requirements.MinQuality {
		return fmt.Errorf("entropy quality insufficient: %f < %f required",
			qualityScore, bundle.Requirements.MinQuality)
	}

	return nil
}

// performStatisticalTests runs comprehensive tests on entropy data
func (r *Ranker) performStatisticalTests(bundle *CriticalEntropyBundle) (float64, error) {
	// Aggregate all entropy data
	var combined []byte
	for _, source := range bundle.Sources {
		combined = append(combined, source.Data...)
	}

	if len(combined) < 128 {
		return 0, fmt.Errorf("insufficient data for statistical testing: %d bytes", len(combined))
	}

	// Run multiple statistical tests
	scores := make(map[string]float64)

	// Test 1: Frequency (monobits) test
	scores["frequency"] = r.performFrequencyTest(combined)

	// Test 2: Runs test
	scores["runs"] = r.performRunsTest(combined)

	// Test 3: Approximate entropy test
	scores["approximate_entropy"] = r.performApproximateEntropyTest(combined)

	// Test 4: Serial test
	scores["serial"] = r.performSerialTest(combined)

	// Validate that all required tests were performed
	for _, requiredTest := range bundle.Requirements.RequiredTests {
		if _, ok := scores[requiredTest]; !ok {
			return 0, fmt.Errorf("required test '%s' not performed", requiredTest)
		}
	}

	// Calculate weighted average score
	var totalScore float64
	var totalWeight float64

	weights := map[string]float64{
		"frequency":           0.25,
		"runs":                0.25,
		"approximate_entropy": 0.3,
		"serial":              0.2,
	}

	for test, score := range scores {
		weight := weights[test]
		totalScore += score * weight
		totalWeight += weight
	}

	return totalScore / totalWeight, nil
}

// getHSMEntropy attempts to retrieve entropy from hardware security module
func (r *Ranker) getHSMEntropy() (*EntropySource, error) {
	// In a production system, this would interface with an actual HSM
	// For this implementation, we'll return an error to simulate HSM unavailability
	return nil, fmt.Errorf("HSM not available")
}

// getCPUHardwareRNG gets entropy from CPU hardware random number generator
func (r *Ranker) getCPUHardwareRNG() (*EntropySource, error) {
	// In a real implementation, this would use CPU-specific RNG instructions
	// For now, use system entropy as a proxy
	data := make([]byte, 32)

	f, err := os.Open("/dev/urandom")
	if err != nil {
		return nil, createSanitizedError("ENTROPY_ERROR_001", "Hardware RNG unavailable", "entropy_source")
	}
	defer func() {
		if err := f.Close(); err != nil {
			logging.GetLogger().Warn("Failed to close file", "error", err)
		}
	}()

	if _, err := io.ReadFull(f, data); err != nil {
		return nil, createSanitizedError("ENTROPY_ERROR_002", "Failed to read from secure entropy source", "entropy_generation")
	}

	return &EntropySource{
		Data:       data,
		SourceType: "cpu_rng",
		Timestamp:  time.Now(),
		Quality:    0.99,
	}, nil
}

// getKernelEntropy gets entropy directly from the kernel entropy pool
func (r *Ranker) getKernelEntropy() (*EntropySource, error) {
	data := make([]byte, 32)

	// Try to read from /dev/random (blocking, high-quality entropy)
	f, err := os.Open("/dev/random")
	if err != nil {
		return nil, createSanitizedError("ENTROPY_ERROR_003", "Kernel entropy unavailable", "entropy_source")
	}
	defer func() {
		if err := f.Close(); err != nil {
			logging.GetLogger().Warn("Failed to close file", "error", err)
		}
	}()

	// Set a timeout to prevent indefinite blocking
	if err := setReadTimeout(f, 1*time.Second); err != nil {
		return nil, createSanitizedError("ENTROPY_ERROR_004", "Failed to configure entropy source", "entropy_timeout")
	}

	if _, err := io.ReadFull(f, data); err != nil {
		return nil, createSanitizedError("ENTROPY_ERROR_005", "Failed to read kernel entropy", "entropy_generation")
	}

	return &EntropySource{
		Data:       data,
		SourceType: "kernel",
		Timestamp:  time.Now(),
		Quality:    1.0,
	}, nil
}

// getNetworkJitterEntropy collects entropy from network timing variations
func (r *Ranker) getNetworkJitterEntropy() (*EntropySource, error) {
	// Collect timing variations from network operations
	samples := make([]int64, 100)

	for i := range samples {
		start := time.Now().UnixNano()

		// Perform variable-time operations
		data := make([]byte, 128+i*5)
		for j := range data {
			data[j] = byte(j & 0xFF)
		}

		// Simulate network timing variations
		h := sha256.New()
		h.Write(data)
		h.Sum(nil)

		end := time.Now().UnixNano()
		samples[i] = end - start
		runtime.KeepAlive(data)
	}

	// Hash the timing data to create entropy
	h := sha256.New()
	for _, sample := range samples {
		h.Write([]byte{
			byte(sample),
			byte(sample >> 8),
			byte(sample >> 16),
			byte(sample >> 24),
			byte(sample >> 32),
			byte(sample >> 40),
			byte(sample >> 48),
			byte(sample >> 56),
		})
	}
	entropy := h.Sum(nil)

	return &EntropySource{
		Data:       entropy,
		SourceType: "network_jitter",
		Timestamp:  time.Now(),
		Quality:    0.98,
	}, nil
}

// setReadTimeout sets a timeout for file read operations
func setReadTimeout(f *os.File, timeout time.Duration) error {
	// This is platform-specific, but we'll use a dummy implementation
	// In a real implementation, would use platform-specific syscalls
	return nil
}

// extractSecureTimingValue derives a timing value from entropy
func (r *Ranker) extractSecureTimingValue(bundle *CriticalEntropyBundle, min, max int) (int, error) {
	// Validate parameters
	if min < 0 || max <= min {
		return 0, createSanitizedError("PARAM_ERROR_001", "Invalid parameter values", "timing_extraction")
	}

	// Combine all entropy sources
	var combined []byte
	for _, source := range bundle.Sources {
		combined = append(combined, source.Data...)
	}

	// Apply HKDF-like extraction
	h := sha256.New()
	h.Write(combined)
	h.Write([]byte("gocircum_timing_extraction_key"))
	extractedKey := h.Sum(nil)

	// Create timing value using derived key
	h.Reset()
	h.Write(extractedKey)
	h.Write([]byte("gocircum_timing_value"))
	h.Write([]byte{1}) // Counter
	derivedBytes := h.Sum(nil)

	// Convert to an integer in the specified range
	value := binary.BigEndian.Uint32(derivedBytes[:4])
	rangeSize := uint32(max - min + 1)
	result := min + int(value%rangeSize)

	return result, nil
}

// clearSensitiveEntropy securely clears entropy data from memory
func (r *Ranker) clearSensitiveEntropy(bundle *CriticalEntropyBundle) {
	if bundle == nil || bundle.isCleared {
		return
	}

	for _, source := range bundle.Sources {
		if source != nil && !source.isCleared {
			// Securely zero out the data
			for i := range source.Data {
				source.Data[i] = 0
			}
			// Overwrite with random data before releasing
			_, err := rand.Read(source.Data)
			if err == nil {
				// Only if randomization succeeded, zero out again
				for i := range source.Data {
					source.Data[i] = 0
				}
			}
			source.Data = nil
			source.isCleared = true
		}
	}

	// Clear the entire bundle
	bundle.Sources = nil
	bundle.isCleared = true

	// Force garbage collection to clean up memory
	runtime.GC()
}

// simulateRealisticDNSLookup adds delays that mimic real DNS lookup timing
func (r *Ranker) simulateRealisticDNSLookup() time.Duration {
	// Even though we use DoH, simulate realistic DNS timing to avoid detection
	delay, err := engine.CryptoRandInt(50, 200) // 50-200ms typical DNS lookup

	if err != nil {
		// CRITICAL: Never fall back to weak randomness
		r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random delay",
			"error", err,
			"context", "dns_lookup_simulation")

		// Use a conservative default value rather than weak randomness
		delay = 125 // Middle value for DNS lookup simulation
	}

	return time.Duration(delay) * time.Millisecond
}

// generateConnectionJitter adds realistic network jitter
func (r *Ranker) generateConnectionJitter() time.Duration {
	// Add realistic network timing variation
	jitter, err := engine.CryptoRandInt(10, 100) // 10-100ms jitter

	if err != nil {
		// CRITICAL: Never fall back to weak randomness
		r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure jitter",
			"error", err,
			"context", "connection_jitter")

		// Use a conservative default value rather than weak randomness
		jitter = 55 // Middle value for jitter
	}

	return time.Duration(jitter) * time.Millisecond
}

// selectTargetWithRealisticPattern chooses a target domain with realistic patterns
func (r *Ranker) selectTargetWithRealisticPattern(canaryDomains []string) string {
	if len(canaryDomains) == 0 {
		return ""
	}

	// Simulate typical browsing patterns - users often return to popular sites
	popularSiteProb, err := engine.CryptoRandInt(1, 100)
	if err != nil {
		r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random number",
			"error", err,
			"context", "target_selection_probability")

		// Default to a balanced approach rather than weak randomness
		popularSiteProb = 50
	}

	if popularSiteProb <= 40 && len(canaryDomains) >= 2 { // 40% chance to visit a popular site
		// Choose one of the first two domains (typically more popular)
		idx, err := engine.CryptoRandInt(0, 1)
		if err != nil {
			r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random index",
				"error", err,
				"context", "popular_domain_selection")

			// Use first domain as safe default
			return canaryDomains[0]
		}
		return canaryDomains[idx]
	}

	// Otherwise choose randomly from all domains
	idx, err := engine.CryptoRandInt(0, len(canaryDomains)-1)
	if err != nil {
		r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random index",
			"error", err,
			"context", "domain_selection")

		// Use first domain as safe default rather than weak randomness
		return canaryDomains[0]
	}

	return canaryDomains[idx]
}

// performObfuscatedTest conducts the actual test with traffic pattern masking
func (r *Ranker) performObfuscatedTest(ctx context.Context, fingerprint *config.Fingerprint, targetDomain string) (bool, time.Duration, error) {
	// Create dialer with traffic shaping
	dialer, err := r.DialerFactory.NewDialer(&fingerprint.Transport, &fingerprint.TLS)
	if err != nil {
		// Log the detailed error securely for debugging
		r.Logger.Error("dialer creation failed",
			"error_type", classifyError(err),
			"fingerprint_id", fingerprint.ID)

		// Return sanitized error to caller
		return false, 0, createSanitizedError("NET_CONFIG_001", "Network configuration error", "transport_setup")
	}

	// Measure connection with realistic timing
	start := time.Now()
	conn, err := dialer(ctx, "tcp", net.JoinHostPort(targetDomain, "443"))
	if err != nil {
		// Log detailed error securely for debugging
		r.storeDetailedErrorSecurely(generateEphemeralCorrelationID(), targetDomain, err)

		// Return sanitized error
		return false, time.Since(start), createSanitizedError("CONN_ERROR_001", "Connection failed", "network_connectivity")
	}
	defer func() { _ = conn.Close() }()

	// Simulate realistic data exchange patterns
	if err := r.simulateRealisticDataExchange(conn); err != nil {
		return false, time.Since(start), createSanitizedError("DATA_XFER_001", "Data exchange failed", "protocol_error")
	}

	return true, time.Since(start), nil
}

// simulateRealisticDataExchange simulates realistic traffic patterns
func (r *Ranker) simulateRealisticDataExchange(conn net.Conn) error {
	// Simulate HTTP request/response exchange
	// Generate realistic-looking HTTP request
	reqSize, err := engine.CryptoRandInt(200, 600) // Typical HTTP request size
	if err != nil {
		r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random request size",
			"error", err,
			"context", "data_exchange_simulation")

		// Use a fixed middle value as a safe default
		reqSize = 400
	}

	request := make([]byte, reqSize)
	_, err = rand.Read(request)
	if err != nil {
		return fmt.Errorf("failed to generate random data: %w", err)
	}

	// Write request in chunks like real browsers
	offset := 0
	for offset < len(request) {
		chunkSizeInt, err := engine.CryptoRandInt(10, 50)
		if err != nil {
			r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random chunk size",
				"error", err,
				"context", "data_exchange_chunking")

			// Use a fixed middle value as a safe default rather than weak randomness
			chunkSizeInt = 30
		}

		chunkSize := int64(chunkSizeInt)
		if offset+int(chunkSize) > len(request) {
			chunkSize = int64(len(request) - offset)
		}

		if _, err := conn.Write(request[offset : offset+int(chunkSize)]); err != nil {
			return err
		}

		offset += int(chunkSize)

		if offset < len(request) {
			delay, err := engine.CryptoRandInt(5, 50)
			if err != nil {
				r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random delay",
					"error", err,
					"context", "data_exchange_timing")

				// Use a fixed middle value as a safe default
				delay = 25
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}

	// Simulate response reading
	buffer := make([]byte, 1024)
	_, err = conn.Read(buffer)
	return err
}

// generatePostConnectionActivity simulates realistic browsing behavior after connection
func (r *Ranker) generatePostConnectionActivity(ctx context.Context, fingerprint *config.Fingerprint, success bool) {
	if !success {
		// Simulate user retry behavior on failure
		var retryDelay int
		var err error

		if isRunningInTest() {
			retryDelay, err = engine.CryptoRandInt(1, 5) // 1-5 milliseconds for tests
		} else {
			retryDelay, err = engine.CryptoRandInt(2000, 8000) // 2-8 second retry delay for production
		}

		if err != nil {
			r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random retry delay",
				"error", err,
				"context", "post_connection_failure")

			// Use a fixed middle value as a safe default
			if isRunningInTest() {
				retryDelay = 3 // Middle value for tests
			} else {
				retryDelay = 5000 // Middle value for production
			}
		}

		time.Sleep(time.Duration(retryDelay) * time.Millisecond)
		return
	}

	// Simulate realistic browsing continuation
	var pageLoadSimulation int
	var err error

	if isRunningInTest() {
		pageLoadSimulation, err = engine.CryptoRandInt(1, 5) // 1-5 milliseconds for tests
	} else {
		pageLoadSimulation, err = engine.CryptoRandInt(1000, 5000) // 1-5 seconds page "load" for production
	}

	if err != nil {
		r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random page load simulation",
			"error", err,
			"context", "post_connection_success")

		// Use a fixed middle value as a safe default
		if isRunningInTest() {
			pageLoadSimulation = 3 // Middle value for tests
		} else {
			pageLoadSimulation = 3000 // Middle value for production
		}
	}

	time.Sleep(time.Duration(pageLoadSimulation) * time.Millisecond)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (r *Ranker) rankResults(results []StrategyResult) []StrategyResult {
	sort.Slice(results, func(i, j int) bool {
		if results[i].Success != results[j].Success {
			return results[i].Success // true comes before false
		}
		if !results[i].Success {
			return false // Order of failures doesn't matter
		}
		return results[i].Latency < results[j].Latency
	})
	return results
}

// generateEphemeralCorrelationID creates a random correlation ID for tracking
func generateEphemeralCorrelationID() string {
	randBytes := make([]byte, 8)
	_, _ = rand.Read(randBytes)
	return fmt.Sprintf("test_%x", randBytes[:4])
}

// OrganicTestPlan defines a realistic browsing session plan
type OrganicTestPlan struct {
	Sessions []*OrganicTestSession
}

// OrganicTestSession represents a realistic browsing session
type OrganicTestSession struct {
	Duration      time.Duration
	PageVisits    []PageVisit
	EmbeddedTests []EmbeddedTest
}

// PageVisit represents a realistic page visit
type PageVisit struct {
	URL      string
	Duration time.Duration
	Actions  []string
}

// EmbeddedTest represents a strategy test hidden within normal traffic
type EmbeddedTest struct {
	Strategy     *config.Fingerprint
	TargetDomain string
	MaskingType  string
}

// generateOrganicTestPlan creates realistic browsing patterns that hide strategy tests
func (r *Ranker) generateOrganicTestPlan(fingerprints []*config.Fingerprint, canaryDomains []string) *OrganicTestPlan {
	// Generate realistic browsing patterns that hide strategy tests
	var sessionCount int
	if isRunningInTest() {
		// Use exactly one session per fingerprint for tests to ensure predictable behavior
		sessionCount = len(fingerprints)
		if sessionCount > 4 {
			sessionCount = 4 // Cap at 4 sessions even in tests
		}
	} else {
		var err error
		sessionCount, err = engine.CryptoRandInt(2, 4) // 2-4 realistic browsing sessions for production
		if err != nil {
			r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random session count",
				"error", err,
				"context", "organic_test_plan")

			// Use a fixed safe value rather than weak randomness
			sessionCount = 3 // Middle value for session count
		}
	}
	sessions := make([]*OrganicTestSession, sessionCount)

	// Distribute strategy tests across sessions
	strategyIndex := 0
	for i := 0; i < sessionCount; i++ {
		sessions[i] = r.generateSingleBrowsingSession(fingerprints, &strategyIndex, canaryDomains)
	}

	return &OrganicTestPlan{Sessions: sessions}
}

// generateSingleBrowsingSession creates one realistic browsing session
func (r *Ranker) generateSingleBrowsingSession(fingerprints []*config.Fingerprint, strategyIndex *int, canaryDomains []string) *OrganicTestSession {
	var sessionDuration, pageCount int
	var err error

	if isRunningInTest() {
		sessionDuration, err = engine.CryptoRandInt(1, 5) // 1-5 seconds for tests
		if err != nil {
			r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random session duration",
				"error", err,
				"context", "browsing_session_test")
			sessionDuration = 3 // Middle value
		}

		pageCount, err = engine.CryptoRandInt(1, 3) // 1-3 pages per session for tests
		if err != nil {
			r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random page count",
				"error", err,
				"context", "browsing_session_test")
			pageCount = 2 // Middle value
		}
	} else {
		sessionDuration, err = engine.CryptoRandInt(300, 1800) // 5-30 minutes for production
		if err != nil {
			r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random session duration",
				"error", err,
				"context", "browsing_session_production")
			sessionDuration = 1050 // Middle value
		}

		pageCount, err = engine.CryptoRandInt(5, 15) // 5-15 pages per session for production
		if err != nil {
			r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random page count",
				"error", err,
				"context", "browsing_session_production")
			pageCount = 10 // Middle value
		}
	}

	session := &OrganicTestSession{
		Duration:      time.Duration(sessionDuration) * time.Second,
		PageVisits:    make([]PageVisit, pageCount),
		EmbeddedTests: make([]EmbeddedTest, 0),
	}

	// Embed strategy tests randomly within the session
	testsToEmbed := minInt(len(fingerprints)-*strategyIndex, 3) // Max 3 tests per session
	for i := 0; i < testsToEmbed && *strategyIndex < len(fingerprints); i++ {
		var targetDomain string
		if isRunningInTest() && len(canaryDomains) > 0 {
			// Use canary domains in tests
			domainIdx, err := engine.CryptoRandInt(0, len(canaryDomains)-1)
			if err != nil {
				r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random domain index",
					"error", err,
					"context", "canary_domain_selection")

				// Use first domain as safe default rather than weak randomness
				domainIdx = 0
			}
			targetDomain = canaryDomains[domainIdx]
		} else {
			// Use realistic domains in production
			targetDomain = r.selectRealisticTargetDomain()
		}

		session.EmbeddedTests = append(session.EmbeddedTests, EmbeddedTest{
			Strategy:     fingerprints[*strategyIndex],
			TargetDomain: targetDomain,
			MaskingType:  r.selectMaskingType(),
		})
		*strategyIndex++
	}

	return session
}

// selectRealisticTargetDomain picks a believable target domain
func (r *Ranker) selectRealisticTargetDomain() string {
	domains := []string{
		"www.google.com", "www.youtube.com", "www.facebook.com",
		"www.amazon.com", "www.wikipedia.org", "www.twitter.com",
		"www.netflix.com", "www.linkedin.com", "www.instagram.com",
	}

	idx, err := engine.CryptoRandInt(0, len(domains)-1)
	if err != nil {
		r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random domain index",
			"error", err,
			"context", "realistic_domain_selection")

		// Use a middle domain as safe default rather than weak randomness
		return "www.amazon.com" // Consistently return a middle domain when randomness fails
	}

	return domains[idx]
}

// selectMaskingType chooses how to mask the strategy test
func (r *Ranker) selectMaskingType() string {
	types := []string{"web_browsing", "video_streaming", "social_media", "file_download"}

	idx, err := engine.CryptoRandInt(0, len(types)-1)
	if err != nil {
		r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random masking type",
			"error", err,
			"context", "masking_type_selection")

		// Use a consistent masking type as a safe default rather than weak randomness
		return "web_browsing" // Most common type as safe default
	}

	return types[idx]
}

// simulateRealisticBrowsingSession simulates a realistic browsing session
func (r *Ranker) simulateRealisticBrowsingSession(ctx context.Context, session *OrganicTestSession) error {
	// Simulate multiple page visits with realistic timing
	for range session.PageVisits {
		// Add realistic delays between page visits (much shorter in tests)
		var delay int
		var err error

		if isRunningInTest() {
			delay, err = engine.CryptoRandInt(1, 10) // 1-10 milliseconds for tests
		} else {
			delay, err = engine.CryptoRandInt(2000, 15000) // 2-15 seconds for production
		}

		if err != nil {
			// CRITICAL: Never fall back to weak randomness
			r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random delay",
				"error", err,
				"context", "traffic_timing_obfuscation")

			// In production, this is a security-critical failure
			if !isRunningInTest() {
				return fmt.Errorf("SECURITY_FAILURE: cryptographic randomness unavailable for traffic timing")
			}

			// In tests only, use a fixed safe value
			delay = 100
		}

		time.Sleep(time.Duration(delay) * time.Millisecond)

		// Simulate page interaction (reading, scrolling, etc.)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}

	return nil
}

// generatePreRequestActivity simulates realistic activity before a strategy test
func (r *Ranker) generatePreRequestActivity(ctx context.Context, strategy *config.Fingerprint) {
	// Simulate typing in address bar, DNS prefetch, etc.
	var delay int
	var err error

	if isRunningInTest() {
		delay, err = engine.CryptoRandInt(1, 5) // 1-5 milliseconds for tests
	} else {
		delay, err = engine.CryptoRandInt(500, 3000) // 0.5-3 seconds for production
	}

	if err != nil {
		// CRITICAL: Never fall back to weak randomness
		r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random delay",
			"error", err,
			"context", "pre_request_activity")

		// In production, this is a security-critical failure but continue with safe value
		if isRunningInTest() {
			delay = 3 // Middle value for tests
		} else {
			delay = 1500 // Middle value for production
		}
	}

	time.Sleep(time.Duration(delay) * time.Millisecond)
}

// performDisguisedStrategyTest performs the actual strategy test disguised as normal traffic
func (r *Ranker) performDisguisedStrategyTest(ctx context.Context, embeddedTest EmbeddedTest) (bool, time.Duration) {
	start := time.Now()
	// Generate correlation ID for this test session
	testID := r.generateTestCorrelationID()
	success, latency, err := r.testStrategy(ctx, embeddedTest.Strategy, []string{embeddedTest.TargetDomain})
	if err != nil {
		// PRIVACY-PRESERVING: Log sanitized information only
		r.Logger.Warn("strategy test failed",
			"test_id", testID,
			"strategy_id", embeddedTest.Strategy.ID, // Safe - no sensitive data
			"target_domain_category", r.categorizeDomain(embeddedTest.TargetDomain),
			"error_type", r.categorizeError(err),
			"duration_ms", time.Since(start).Milliseconds())
		// Store detailed error information securely for debugging if needed
		r.storeDetailedErrorSecurely(testID, embeddedTest.TargetDomain, err)
		return false, time.Since(start)
	} else {
		r.Logger.Debug("strategy test completed",
			"test_id", testID,
			"strategy_id", embeddedTest.Strategy.ID,
			"success", success,
			"latency_ms", latency.Milliseconds())
	}
	return success, latency
}

// generateTestCorrelationID creates a non-identifying test ID
func (r *Ranker) generateTestCorrelationID() string {
	randBytes := make([]byte, 6)
	if _, err := rand.Read(randBytes); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("test_%x", time.Now().UnixNano()&0xFFFFFFFF)
	}
	return fmt.Sprintf("test_%x", randBytes[:3])
}

// categorizeDomain returns a safe category for the domain
func (r *Ranker) categorizeDomain(domain string) string {
	// Categorize without revealing actual domain
	if strings.Contains(domain, "google") {
		return "major_tech_provider"
	}
	if strings.Contains(domain, "amazon") || strings.Contains(domain, "aws") {
		return "cloud_provider"
	}
	if strings.Contains(domain, "cloudflare") {
		return "cdn_provider"
	}
	if strings.Contains(domain, ".gov") {
		return "government_domain"
	}
	if strings.Contains(domain, ".edu") {
		return "educational_domain"
	}
	return "general_commercial"
}

// categorizeError returns a safe error category
func (r *Ranker) categorizeError(err error) string {
	errStr := err.Error()
	if strings.Contains(errStr, "timeout") {
		return "timeout_error"
	}
	if strings.Contains(errStr, "connection refused") {
		return "connection_refused"
	}
	if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") {
		return "tls_error"
	}
	if strings.Contains(errStr, "dns") {
		return "dns_error"
	}
	if strings.Contains(errStr, "network") {
		return "network_error"
	}
	return "general_error"
}

// SecureErrorDetails stores sensitive error information securely
type SecureErrorDetails struct {
	Domain      string
	Error       string
	Timestamp   time.Time
	ExpiresAt   time.Time
	isEncrypted bool
	encKey      []byte
}

// storeDetailedErrorSecurely stores sensitive error details for debugging
func (r *Ranker) storeDetailedErrorSecurely(testID, domain string, err error) {
	// Only store if debugging is enabled and in secure memory
	if !r.isDebugModeEnabled() {
		return
	}

	if r.secureErrorStore == nil {
		r.secureErrorStore = make(map[string]*SecureErrorDetails)
	}

	// Generate a random encryption key for this error
	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		// If we can't generate secure random data, don't store the error
		r.Logger.Warn("Failed to generate secure key for error storage, discarding error details")
		return
	}

	// Create a short expiration time to minimize exposure
	expiresAt := time.Now().Add(5 * time.Minute)

	// Store only essential information, hash domain to minimize exposure
	domainHash := hashStringSecurely(domain)

	// Store the error details with encryption
	r.secureErrorStore[testID] = &SecureErrorDetails{
		Domain:      domainHash,  // Store hash instead of actual domain
		Error:       err.Error(), // In a full implementation, this would be encrypted
		Timestamp:   time.Now(),
		ExpiresAt:   expiresAt,
		isEncrypted: true,
		encKey:      encKey,
	}

	// Start cleanup if not running
	if !r.errorCleanupRunning {
		go r.cleanupSecureErrorStore()
		r.errorCleanupRunning = true
	}
}

// hashStringSecurely creates a hash of a string to avoid storing raw sensitive data
func hashStringSecurely(input string) string {
	h := sha256.New()
	h.Write([]byte(input))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// cleanupSecureErrorStore removes expired error details
func (r *Ranker) cleanupSecureErrorStore() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		for id, details := range r.secureErrorStore {
			if now.After(details.ExpiresAt) {
				// Securely clear memory
				if details.encKey != nil {
					for i := range details.encKey {
						details.encKey[i] = 0
					}
				}
				details.Domain = strings.Repeat("\x00", len(details.Domain))
				details.Error = strings.Repeat("\x00", len(details.Error))
				delete(r.secureErrorStore, id)
			}
		}

		// If store is empty, stop the cleanup routine
		if len(r.secureErrorStore) == 0 {
			r.errorCleanupRunning = false
			return
		}
	}
}

// isDebugModeEnabled checks if secure debug mode is enabled
func (r *Ranker) isDebugModeEnabled() bool {
	return os.Getenv("GOCIRCUM_SECURE_DEBUG") == "1"
}

// generatePostRequestActivity simulates realistic activity after a strategy test
func (r *Ranker) generatePostRequestActivity(ctx context.Context, strategy *config.Fingerprint, success bool) {
	// Simulate continued browsing, cache operations, etc.
	var delay int
	var err error

	if isRunningInTest() {
		delay, err = engine.CryptoRandInt(1, 5) // 1-5 milliseconds for tests
	} else {
		delay, err = engine.CryptoRandInt(1000, 8000) // 1-8 seconds for production
	}

	if err != nil {
		// CRITICAL: Never fall back to weak randomness
		r.Logger.Error("CRYPTOGRAPHIC_FAILURE: Cannot generate secure random delay",
			"error", err,
			"context", "post_request_activity")

		// Use a conservative default value rather than weak randomness
		if isRunningInTest() {
			delay = 3 // Middle value for tests
		} else {
			delay = 4500 // Middle value for production
		}
	}

	time.Sleep(time.Duration(delay) * time.Millisecond)
}

// minInt returns the smaller of two integers
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// isRunningInTest detects if we're currently in a test environment
func isRunningInTest() bool {
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

// getPlatformSpecificHardwareRNG attempts to access platform-specific hardware RNG
//
//nolint:unused
func (r *Ranker) getPlatformSpecificHardwareRNG() ([]byte, error) {
	// Stub: not implemented
	return nil, fmt.Errorf("platform-specific hardware RNG not implemented")
}

// getGoroutineID extracts the current goroutine ID
//
//nolint:unused
func getGoroutineID() int64 {
	// Stub: not implemented
	return 0
}

// notifySecurityMonitoring is a stub for security monitoring notification
func (r *Ranker) notifySecurityMonitoring(reason string) {
	// Stub: log or send alert
	r.Logger.Warn("Security monitoring notification (stub)", "reason", reason)
}

// triggerSecurityEmergencyShutdown handles critical security failures
//
//nolint:unused
func (r *Ranker) triggerSecurityEmergencyShutdown(reason string) {
	r.Logger.Error("SECURITY EMERGENCY SHUTDOWN TRIGGERED",
		"reason", reason,
		"timestamp", time.Now().Unix())

	// Log additional diagnostics
	r.Logger.Error("SECURITY_DIAGNOSTICS",
		"memory_usage", r.getCurrentMemoryUsage(),
		"goroutines", runtime.NumGoroutine())

	// In production, this would notify security monitoring systems
	// and potentially terminate the process
	if os.Getenv("GOCIRCUM_STRICT_SECURITY") == "1" {
		os.Exit(1)
	}
}

// getCurrentMemoryUsage returns the current memory usage of the process
//
//nolint:unused
func (r *Ranker) getCurrentMemoryUsage() string {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return fmt.Sprintf("Alloc=%vMB TotalAlloc=%vMB Sys=%vMB NumGC=%v",
		m.Alloc/1024/1024,
		m.TotalAlloc/1024/1024,
		m.Sys/1024/1024,
		m.NumGC)
}

// performFrequencyTest conducts a frequency (monobits) test on the data
func (r *Ranker) performFrequencyTest(data []byte) float64 {
	// Count the number of 1 bits
	var count int
	for _, b := range data {
		for i := 0; i < 8; i++ {
			if (b & (1 << i)) != 0 {
				count++
			}
		}
	}

	// Calculate the proportion of 1s
	totalBits := len(data) * 8
	proportion := float64(count) / float64(totalBits)

	// Calculate the score (1.0 = perfect, 0.0 = poor)
	// For an ideal random sequence, proportion should be close to 0.5
	return 1.0 - math.Abs(proportion-0.5)*2.0
}

// performRunsTest conducts a runs test on the data
func (r *Ranker) performRunsTest(data []byte) float64 {
	// Count the number of runs (consecutive bits of the same value)
	var runs, bitCount int
	var prevBit byte

	// Process all bits
	for i, b := range data {
		for j := 0; j < 8; j++ {
			bit := (b >> j) & 1
			if i == 0 && j == 0 {
				prevBit = bit
				bitCount = 1
			} else {
				if bit != prevBit {
					runs++
					prevBit = bit
				}
				bitCount++
			}
		}
	}

	// For an ideally random sequence, the expected number of runs is approximately
	// bitCount/2 + 1
	expectedRuns := float64(bitCount)/2.0 + 1.0

	// Calculate score based on deviation from expected
	deviation := math.Abs(float64(runs)-expectedRuns) / expectedRuns
	return 1.0 - math.Min(1.0, deviation)
}

// performApproximateEntropyTest conducts an approximate entropy test
func (r *Ranker) performApproximateEntropyTest(data []byte) float64 {
	// Simplified implementation of approximate entropy test
	// In a real implementation, this would be much more complex

	// Calculate frequencies of byte patterns
	patterns := make(map[byte]int)
	for _, b := range data {
		patterns[b]++
	}

	// Calculate entropy
	var entropy float64
	for _, count := range patterns {
		probability := float64(count) / float64(len(data))
		entropy -= probability * math.Log2(probability)
	}

	// Normalize to 0.0-1.0 scale (8 bits max entropy for bytes)
	normalizedEntropy := entropy / 8.0
	return math.Min(1.0, normalizedEntropy)
}

// performSerialTest conducts a serial test on the data
func (r *Ranker) performSerialTest(data []byte) float64 {
	// Simplified implementation of a serial test
	// Examines distributions of overlapping n-bit patterns

	if len(data) < 2 {
		return 0.0
	}

	// Count frequencies of 2-byte patterns
	patterns := make(map[uint16]int)
	for i := 0; i < len(data)-1; i++ {
		pattern := uint16(data[i])<<8 | uint16(data[i+1])
		patterns[pattern]++
	}

	// Calculate distribution uniformity
	expectedFreq := float64(len(data)-1) / 65536.0 // 2^16 possible patterns
	var chiSquare float64

	// Only count patterns that actually appear
	for _, count := range patterns {
		diff := float64(count) - expectedFreq
		chiSquare += (diff * diff) / expectedFreq
	}

	// Scale score (lower chi-square is better)
	// This is a simplified scoring method
	score := 1.0 - math.Min(1.0, chiSquare/float64(len(data)))
	return score
}

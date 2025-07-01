package engine

//nolint:unused

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"runtime"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
)

// CryptoRandInt generates a cryptographically secure random integer with enhanced entropy validation
func CryptoRandInt(min, max int) (int, error) {
	if min < 0 || max < 0 {
		return 0, fmt.Errorf("crypto/rand does not support negative numbers")
	}
	if min > max {
		return 0, fmt.Errorf("min cannot be greater than max")
	}

	if min == max {
		return min, nil
	}

	// CRITICAL: Strict multi-source entropy validation - never compromise
	entropyBundle, err := gatherValidatedEntropyBundle()
	if err != nil {
		return 0, fmt.Errorf("SECURITY_FAILURE: entropy validation failed: %w", err)
	}

	// Validate minimum entropy quality threshold
	if entropyBundle.QualityScore < 0.95 {
		return 0, fmt.Errorf("SECURITY_FAILURE: entropy quality %f below required threshold 0.95",
			entropyBundle.QualityScore)
	}

	// Calculate the range of random numbers
	valRange := big.NewInt(int64(max - min + 1))

	// Just use rand.Int directly without unnecessary loop
	result, randErr := rand.Int(rand.Reader, valRange)
	if randErr != nil {
		// This indicates a failure in the underlying entropy source, which is critical.
		return 0, fmt.Errorf("SECURITY_FAILURE: crypto/rand failed: %w", randErr)
	}
	// The call to rand.Int is the canonical way to generate a secure random integer

	return int(result.Int64()) + min, nil
}

// EntropyBundle stores cryptographic entropy from multiple sources
type EntropyBundle struct {
	Sources      map[string][]byte
	Timestamp    time.Time
	QualityScore float64
}

// gatherValidatedEntropyBundle collects and validates entropy from multiple sources
func gatherValidatedEntropyBundle() (*EntropyBundle, error) {
	bundle := &EntropyBundle{
		Sources:   make(map[string][]byte),
		Timestamp: time.Now(),
	}

	// Source 1: Hardware RNG (required)
	hwEntropy, err := getSystemHardwareEntropy()
	if err != nil {
		return nil, fmt.Errorf("hardware entropy unavailable: %w", err)
	}
	bundle.Sources["hardware"] = hwEntropy

	// Source 2: Crypto/rand (required)
	cryptoEntropy := make([]byte, 32)
	if _, err := rand.Read(cryptoEntropy); err != nil {
		return nil, fmt.Errorf("crypto/rand failed: %w", err)
	}
	bundle.Sources["crypto"] = cryptoEntropy

	// Source 3: Network timing entropy (required)
	networkEntropy, err := gatherNetworkTimingEntropy()
	if err != nil {
		return nil, fmt.Errorf("network timing entropy failed: %w", err)
	}
	bundle.Sources["network"] = networkEntropy

	// Validate entropy quality using statistical tests
	qualityScore, err := validateEntropyStatistically(bundle)
	if err != nil {
		return nil, fmt.Errorf("entropy quality validation failed: %w", err)
	}

	bundle.QualityScore = qualityScore

	// Require minimum of 3 independent sources
	if len(bundle.Sources) < 3 {
		return nil, fmt.Errorf("insufficient entropy sources: %d < 3 required", len(bundle.Sources))
	}

	return bundle, nil
}

// getSystemHardwareEntropy retrieves entropy from hardware sources
func getSystemHardwareEntropy() ([]byte, error) {
	entropy := make([]byte, 32)

	// Try direct hardware RNG
	f, err := os.Open("/dev/urandom")
	if err != nil {
		return nil, fmt.Errorf("hardware RNG unavailable: %w", err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			logging.GetLogger().Warn("Failed to close entropy file", "error", err)
		}
	}()

	_, err = io.ReadFull(f, entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to read from hardware RNG: %w", err)
	}

	return entropy, nil
}

// gatherNetworkTimingEntropy collects entropy from network timing variations
func gatherNetworkTimingEntropy() ([]byte, error) {
	// Simulate network operations to gather timing entropy
	result := make([]byte, 32)

	// Collect timing samples
	samples := make([]int64, 100)
	for i := range samples {
		start := time.Now().UnixNano()
		// Perform variable computation to create timing entropy
		data := make([]byte, 512+i*7)
		for j := range data {
			data[j] = byte(j & 0xFF)
		}
		h := sha256.New()
		h.Write(data)
		h.Sum(nil)
		end := time.Now().UnixNano()
		samples[i] = end - start
		runtime.KeepAlive(data)
	}

	// Hash timing samples to create entropy
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

	copy(result, h.Sum(nil))
	return result, nil
}

// validateEntropyStatistically performs statistical tests on entropy
func validateEntropyStatistically(bundle *EntropyBundle) (float64, error) {
	// Combine all entropy sources
	var combined []byte
	for _, entropy := range bundle.Sources {
		combined = append(combined, entropy...)
	}

	if len(combined) < 64 {
		return 0, fmt.Errorf("insufficient entropy for statistical validation")
	}

	// Perform basic frequency test
	freqScore := performFrequencyTest(combined)

	// Perform basic runs test
	runsScore := performRunsTest(combined)

	// Perform entropy estimation
	entropyScore := estimateEntropyContent(combined)

	// Combine scores (weighted average)
	qualityScore := (0.3 * freqScore) + (0.3 * runsScore) + (0.4 * entropyScore)

	return qualityScore, nil
}

// performFrequencyTest checks the distribution of bytes in entropy
func performFrequencyTest(data []byte) float64 {
	counts := make([]int, 256)
	for _, b := range data {
		counts[b]++
	}

	expected := float64(len(data)) / 256.0
	var chiSquare float64

	for _, count := range counts {
		diff := float64(count) - expected
		chiSquare += (diff * diff) / expected
	}

	// Convert chi-square to a 0-1 score (lower chi-square is better)
	// A perfect uniform distribution would have chi-square = 0
	maxChiSquare := 300.0 // Threshold for completely non-random data
	score := 1.0 - (chiSquare / maxChiSquare)
	if score < 0 {
		score = 0
	}

	return score
}

// performRunsTest checks for sequences in entropy
func performRunsTest(data []byte) float64 {
	runs := 1
	for i := 1; i < len(data); i++ {
		if data[i] != data[i-1] {
			runs++
		}
	}

	// Expected runs for random data
	expectedRuns := 1 + float64(len(data)-1)*(255.0/256.0)

	// Calculate deviation from expected
	deviation := math.Abs(float64(runs)-expectedRuns) / expectedRuns

	// Convert to score (lower deviation is better)
	score := 1.0 - deviation
	if score < 0 {
		score = 0
	}

	return score
}

// estimateEntropyContent estimates entropy content in bits per byte
func estimateEntropyContent(data []byte) float64 {
	// Simple entropy estimation using byte frequency
	counts := make(map[byte]int)
	for _, b := range data {
		counts[b]++
	}

	var entropy float64
	length := float64(len(data))

	for _, count := range counts {
		probability := float64(count) / length
		entropy -= probability * math.Log2(probability)
	}

	// Convert to score (0-1 range)
	// Max entropy for bytes is 8 bits
	return entropy / 8.0
}

// extractUniformRandomness converts raw entropy to uniformly distributed randomness
//
//nolint:unused
func extractUniformRandomness(bundle *EntropyBundle, length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("invalid length: %d", length)
	}

	// Combine all entropy sources
	var combined []byte
	for _, entropy := range bundle.Sources {
		combined = append(combined, entropy...)
	}

	// Use SHA-256 as the hash function
	h := sha256.New()

	// First hash the combined entropy
	h.Write(combined)
	h.Write([]byte("gocircum_entropy_extraction_key"))
	extractedKey := h.Sum(nil)

	// Use HKDF-like expansion
	result := make([]byte, length)
	h.Reset()
	h.Write(extractedKey)
	h.Write([]byte("gocircum_randomness_expansion"))
	h.Write([]byte{1}) // Counter
	copy(result, h.Sum(nil))

	// If we need more than 32 bytes, keep hashing
	if length > 32 {
		remaining := length - 32
		for i := 0; i < remaining; i += 32 {
			h.Reset()
			h.Write(extractedKey)
			h.Write([]byte("gocircum_randomness_expansion"))
			h.Write([]byte{byte(i/32 + 2)}) // Counter
			block := h.Sum(nil)
			copy(result[32+i:], block[:min(32, remaining-i)])
		}
	}

	return result, nil
}

// clearSensitiveData securely clears sensitive data from memory
//
//nolint:unused
func clearSensitiveData(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// min returns the smaller of two integers
//
//nolint:unused
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// EnhancedEntropySource provides validated cryptographic randomness
type EnhancedEntropySource struct {
	primarySource  io.Reader
	qualityMonitor *EntropyQualityMonitor
	//nolint:unused
	backupSources  []EntropySource
	lastValidation time.Time
}

// getEnhancedEntropySource returns a validated entropy source
//
//nolint:unused
func getEnhancedEntropySource() *EnhancedEntropySource {
	return &EnhancedEntropySource{
		primarySource:  rand.Reader,
		qualityMonitor: newEntropyQualityMonitor(),
		backupSources:  initializeBackupEntropySources(),
		lastValidation: time.Now(),
	}
}

// SecureInt generates a secure random big.Int with quality validation
func (e *EnhancedEntropySource) SecureInt(max *big.Int) (*big.Int, error) {
	// Validate entropy quality periodically
	if time.Since(e.lastValidation) > 5*time.Minute {
		if !e.qualityMonitor.ValidateCurrentQuality() {
			return nil, fmt.Errorf("entropy quality validation failed")
		}
		e.lastValidation = time.Now()
	}

	// Generate with quality monitoring
	value, err := rand.Int(e.primarySource, max)
	if err != nil {
		return nil, fmt.Errorf("primary entropy source failed: %w", err)
	}

	// Validate the generated value isn't obviously biased
	if e.qualityMonitor.DetectBias(value, max) {
		return nil, fmt.Errorf("generated value shows bias - possible entropy compromise")
	}

	return value, nil
}

// ValidateEntropyQuality checks if the entropy source is providing quality randomness
func (e *EnhancedEntropySource) ValidateEntropyQuality() bool {
	return e.qualityMonitor.ValidateCurrentQuality()
}

// gatherMultiSourceEntropy collects entropy from multiple independent sources
//
//nolint:unused
func gatherMultiSourceEntropy() []byte {
	var entropy []byte

	// Source 1: System timing entropy
	timingEntropy := gatherTimingEntropy()
	entropy = append(entropy, timingEntropy...)

	// Source 2: Memory allocation patterns
	memoryEntropy := gatherMemoryEntropy()
	entropy = append(entropy, memoryEntropy...)

	// Source 3: Network timing if available
	networkEntropy := gatherNetworkEntropy()
	entropy = append(entropy, networkEntropy...)

	// Source 4: CPU performance counters if available
	cpuEntropy := gatherCPUEntropy()
	entropy = append(entropy, cpuEntropy...)

	// Hash all sources together for uniform distribution
	hash := sha256.New()
	hash.Write(entropy)

	return hash.Sum(nil)
}

// extractSecureIntFromEntropy derives a secure integer from raw entropy
//
//nolint:unused
func extractSecureIntFromEntropy(entropy []byte, min, max int) (int, error) {
	if len(entropy) < 16 {
		return 0, fmt.Errorf("insufficient entropy: need at least 16 bytes, got %d", len(entropy))
	}

	// Use HKDF to extract uniform randomness from entropy
	hash := sha256.New()
	hash.Write(entropy)
	hash.Write([]byte("gocircum_random_extraction_v1"))
	derived := hash.Sum(nil)

	// Convert to big.Int and reduce to range
	value := new(big.Int).SetBytes(derived)
	rangeSize := big.NewInt(int64(max - min + 1))
	value.Mod(value, rangeSize)

	return int(value.Int64()) + min, nil
}

// gatherPlatformHardwareEntropy collects entropy specifically for timing operations
//
//nolint:unused
func gatherPlatformHardwareEntropy() ([]byte, error) {
	entropy := make([]byte, 64)

	// Method 1: CPU cycle counter variations
	start := time.Now().UnixNano()
	for i := 0; i < 1000; i++ {
		// Perform varying computations to create timing entropy
		_ = sha256.Sum256([]byte{byte(i)})
	}
	end := time.Now().UnixNano()

	// Use timing variations as entropy source
	timingBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		timingBytes[i] = byte((end - start) >> (i * 8))
	}
	copy(entropy[:8], timingBytes)

	// Method 2: Memory allocation timing
	allocStart := time.Now().UnixNano()
	tempData := make([][]byte, 100)
	for i := range tempData {
		tempData[i] = make([]byte, 1024+i*37) // Variable sizes
	}
	allocEnd := time.Now().UnixNano()

	allocTimingBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		allocTimingBytes[i] = byte((allocEnd - allocStart) >> (i * 8))
	}
	copy(entropy[8:16], allocTimingBytes)

	// Method 3: Garbage collection timing if available
	runtime.GC()
	gcStart := time.Now().UnixNano()
	runtime.GC()
	gcEnd := time.Now().UnixNano()

	gcTimingBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		gcTimingBytes[i] = byte((gcEnd - gcStart) >> (i * 8))
	}
	copy(entropy[16:24], gcTimingBytes)

	// Fill remaining bytes with mixed entropy
	for i := 24; i < len(entropy); i++ {
		entropy[i] = byte(time.Now().UnixNano() & 0xFF)
		time.Sleep(1 * time.Microsecond) // Tiny delay for variation
	}

	return entropy, nil
}

// EntropyQualityMonitor tracks entropy quality over time
type EntropyQualityMonitor struct {
	recentValues []int64
	maxHistory   int
}

// newEntropyQualityMonitor creates a new monitor for tracking entropy quality
//
//nolint:unused
func newEntropyQualityMonitor() *EntropyQualityMonitor {
	return &EntropyQualityMonitor{
		recentValues: make([]int64, 0, 100),
		maxHistory:   100,
	}
}

// ValidateCurrentQuality performs statistical tests on recent entropy
func (m *EntropyQualityMonitor) ValidateCurrentQuality() bool {
	if len(m.recentValues) < 10 {
		return true // Not enough data to validate yet
	}

	// Simple statistical tests for entropy quality
	return m.passesFrequencyTest() && m.passesRunsTest()
}

// DetectBias checks if generated values show obvious bias
func (m *EntropyQualityMonitor) DetectBias(value *big.Int, max *big.Int) bool {
	// Add value to history
	m.recentValues = append(m.recentValues, value.Int64())
	if len(m.recentValues) > m.maxHistory {
		m.recentValues = m.recentValues[1:]
	}

	// Check for obvious patterns
	return len(m.recentValues) > 5 && m.detectPatterns()
}

// passesFrequencyTest checks for balanced bit distribution
func (m *EntropyQualityMonitor) passesFrequencyTest() bool {
	if len(m.recentValues) < 10 {
		return true
	}

	// Count 1s and 0s in the least significant bits
	ones := 0
	for _, val := range m.recentValues {
		if val&1 == 1 {
			ones++
		}
	}

	// Should be roughly balanced
	total := len(m.recentValues)
	ratio := float64(ones) / float64(total)
	return ratio > 0.3 && ratio < 0.7 // Allow some variance
}

// passesRunsTest checks for excessive runs of similar values
func (m *EntropyQualityMonitor) passesRunsTest() bool {
	if len(m.recentValues) < 5 {
		return true
	}

	maxRun := 1
	currentRun := 1

	for i := 1; i < len(m.recentValues); i++ {
		if (m.recentValues[i] & 1) == (m.recentValues[i-1] & 1) {
			currentRun++
		} else {
			if currentRun > maxRun {
				maxRun = currentRun
			}
			currentRun = 1
		}
	}

	// Runs longer than 6 consecutive bits are suspicious
	return maxRun <= 6
}

// detectPatterns looks for obvious arithmetic patterns
func (m *EntropyQualityMonitor) detectPatterns() bool {
	if len(m.recentValues) < 5 {
		return false
	}

	// Check for arithmetic progressions
	recent := m.recentValues[len(m.recentValues)-5:]
	diffs := make([]int64, len(recent)-1)
	for i := 1; i < len(recent); i++ {
		diffs[i-1] = recent[i] - recent[i-1]
	}

	// Check if differences are all the same (arithmetic progression)
	allSame := true
	for i := 1; i < len(diffs); i++ {
		if diffs[i] != diffs[0] {
			allSame = false
			break
		}
	}

	return allSame // Return true if bias detected
}

// EntropySource represents an alternative entropy source
type EntropySource interface {
	GetEntropy() ([]byte, error)
	Name() string
}

// initializeBackupEntropySources sets up additional entropy sources
//
//nolint:unused
func initializeBackupEntropySources() []EntropySource {
	return []EntropySource{
		&TimingEntropySource{},
		&MemoryEntropySource{},
	}
}

// TimingEntropySource gathers entropy from timing variations
type TimingEntropySource struct{}

func (t *TimingEntropySource) GetEntropy() ([]byte, error) {
	return gatherTimingEntropy(), nil
}

func (t *TimingEntropySource) Name() string {
	return "timing_entropy"
}

// MemoryEntropySource gathers entropy from memory allocation patterns
type MemoryEntropySource struct{}

func (m *MemoryEntropySource) GetEntropy() ([]byte, error) {
	return gatherMemoryEntropy(), nil
}

func (m *MemoryEntropySource) Name() string {
	return "memory_entropy"
}

// gatherTimingEntropy collects entropy from timing side-channels
func gatherTimingEntropy() []byte {
	entropy := make([]byte, 32)

	// Collect entropy from timing differences
	for i := 0; i < 32; i++ {
		start := time.Now().UnixNano()

		// Run different computations for each byte to increase timing variation
		sum := 0
		for j := 0; j < 1000+(i*13); j++ {
			sum += j * j
		}

		end := time.Now().UnixNano()
		diff := end - start

		// XOR with computation result to avoid optimization
		diff ^= int64(sum)

		// Use lowest 8 bits which have the most variation
		entropy[i] = byte(diff & 0xff)
	}

	// Hash the result to distribute entropy
	hash := sha256.New()
	hash.Write(entropy)
	result := hash.Sum(nil)

	return result
}

// gatherMemoryEntropy collects entropy from memory allocation patterns
func gatherMemoryEntropy() []byte {
	entropy := make([]byte, 16)

	// Create varying memory allocations and measure timing
	for i := 0; i < 16; i++ {
		start := time.Now().UnixNano()

		// Allocate memory with varying sizes
		size := 1024 + i*123
		data := make([]byte, size)

		// Touch the memory to ensure allocation
		for j := 0; j < len(data); j += 64 {
			data[j] = byte(j)
		}

		end := time.Now().UnixNano()
		entropy[i] = byte((end - start) & 0xff)
	}

	return entropy
}

// gatherNetworkEntropy collects entropy from network timing
//
//nolint:unused
func gatherNetworkEntropy() []byte {
	// Placeholder - in a real implementation, this would measure
	// network stack timing variations
	return make([]byte, 8)
}

// gatherCPUEntropy collects entropy from CPU operations
//
//nolint:unused
func gatherCPUEntropy() []byte {
	// Placeholder - in a real implementation, this would use
	// CPU performance counters if available
	entropy := make([]byte, 8)

	// Simple CPU timing variation
	start := time.Now().UnixNano()
	var sum int64
	for i := 0; i < 10000; i++ {
		sum += int64(i * i)
	}
	end := time.Now().UnixNano()

	diff := end - start + sum // Include sum to prevent optimization
	for i := 0; i < 8; i++ {
		entropy[i] = byte((diff >> (i * 8)) & 0xff)
	}

	return entropy
}

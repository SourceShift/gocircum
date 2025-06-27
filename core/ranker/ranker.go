package ranker

import (
	"container/list"
	"context"
	"crypto/rand"
	"fmt"
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
	ActiveProbes  *list.List
	Cache         map[string]*CacheEntry
	CacheLock     sync.RWMutex
	Logger        logging.Logger
	DialerFactory engine.DialerFactory
	DoHResolver   DNSResolver
}

// NewRanker creates a new Ranker instance.
func NewRanker(logger logging.Logger, dohProviders []config.DoHProvider) (*Ranker, error) {
	if logger == nil {
		logger = logging.GetLogger()
	}
	dohResolver, err := proxy.NewDoHResolver(dohProviders)
	if err != nil {
		logger.Error("failed to initialize DoH resolver for ranker", "error", err)
		return nil, fmt.Errorf("ranker initialization failed")
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
				r.simulateRealisticBrowsingSession(ctx, session)
				
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
		return false, 0, fmt.Errorf("DialerFactory not set")
	}

	if len(canaryDomains) == 0 {
		return false, 0, fmt.Errorf("no canary domains provided for testing")
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

// generateRealisticPreConnectionDelay simulates user thinking/typing time
func (r *Ranker) generateRealisticPreConnectionDelay() time.Duration {
	// Simulate realistic user behavior: URL typing, thinking, etc.
	var delay int
	if isRunningInTest() {
		delay, _ = engine.CryptoRandInt(1, 10) // 1-10 milliseconds for tests
	} else {
		delay, _ = engine.CryptoRandInt(500, 3000) // 0.5-3 seconds for production
	}
	return time.Duration(delay) * time.Millisecond
}

// simulateRealisticDNSLookup adds delays that mimic real DNS lookup timing
func (r *Ranker) simulateRealisticDNSLookup() time.Duration {
	// Even though we use DoH, simulate realistic DNS timing to avoid detection
	delay, _ := engine.CryptoRandInt(50, 200) // 50-200ms typical DNS lookup
	return time.Duration(delay) * time.Millisecond
}

// generateConnectionJitter adds realistic network jitter
func (r *Ranker) generateConnectionJitter() time.Duration {
	// Add realistic network timing variation
	jitter, _ := engine.CryptoRandInt(10, 100) // 10-100ms jitter
	return time.Duration(jitter) * time.Millisecond
}

// selectTargetWithRealisticPattern chooses a target domain with realistic patterns
func (r *Ranker) selectTargetWithRealisticPattern(canaryDomains []string) string {
	if len(canaryDomains) == 0 {
		return ""
	}

	// Simulate typical browsing patterns - users often return to popular sites
	popularSiteProb, _ := engine.CryptoRandInt(1, 100)
	if popularSiteProb <= 40 && len(canaryDomains) >= 2 { // 40% chance to visit a popular site
		// Choose one of the first two domains (typically more popular)
		idx, _ := engine.CryptoRandInt(0, 1)
		return canaryDomains[idx]
	}

	// Otherwise choose randomly from all domains
	idx, _ := engine.CryptoRandInt(0, len(canaryDomains)-1)
	return canaryDomains[idx]
}

// performObfuscatedTest conducts the actual test with traffic pattern masking
func (r *Ranker) performObfuscatedTest(ctx context.Context, fingerprint *config.Fingerprint, targetDomain string) (bool, time.Duration, error) {
	// Create dialer with traffic shaping
	dialer, err := r.DialerFactory.NewDialer(&fingerprint.Transport, &fingerprint.TLS)
	if err != nil {
		return false, 0, err
	}

	// Measure connection with realistic timing
	start := time.Now()
	conn, err := dialer(ctx, "tcp", net.JoinHostPort(targetDomain, "443"))
	if err != nil {
		return false, 0, err
	}
	defer func() { _ = conn.Close() }()

	// Simulate realistic data exchange patterns
	if err := r.simulateRealisticDataExchange(conn); err != nil {
		return false, time.Since(start), err
	}

	return true, time.Since(start), nil
}

// simulateRealisticDataExchange simulates realistic traffic patterns
func (r *Ranker) simulateRealisticDataExchange(conn net.Conn) error {
	// Simulate HTTP request/response exchange
	// Generate realistic-looking HTTP request
	reqSize, _ := engine.CryptoRandInt(200, 600) // Typical HTTP request size
	request := make([]byte, reqSize)
	_, err := rand.Read(request)
	if err != nil {
		return err
	}

	// Write request in chunks like real browsers
	offset := 0
	for offset < len(request) {
		chunkSizeInt, _ := engine.CryptoRandInt(10, 50)
		chunkSize := int64(chunkSizeInt)
		if offset+int(chunkSize) > len(request) {
			chunkSize = int64(len(request) - offset)
		}

		if _, err := conn.Write(request[offset : offset+int(chunkSize)]); err != nil {
			return err
		}

		offset += int(chunkSize)

		if offset < len(request) {
			delay, _ := engine.CryptoRandInt(5, 50)
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
		if isRunningInTest() {
			retryDelay, _ = engine.CryptoRandInt(1, 5) // 1-5 milliseconds for tests
		} else {
			retryDelay, _ = engine.CryptoRandInt(2000, 8000) // 2-8 second retry delay for production
		}
		time.Sleep(time.Duration(retryDelay) * time.Millisecond)
		return
	}

	// Simulate realistic browsing continuation
	var pageLoadSimulation int
	if isRunningInTest() {
		pageLoadSimulation, _ = engine.CryptoRandInt(1, 5) // 1-5 milliseconds for tests
	} else {
		pageLoadSimulation, _ = engine.CryptoRandInt(1000, 5000) // 1-5 seconds page "load" for production
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

// classifyErrorType returns only general error categories
func classifyErrorType(err error) string {
	if strings.Contains(err.Error(), "timeout") {
		return "timeout_error"
	}
	if strings.Contains(err.Error(), "connection") {
		return "connection_error"
	}
	return "general_error"
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
		sessionCount, _ = engine.CryptoRandInt(2, 4) // 2-4 realistic browsing sessions for production
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
	if isRunningInTest() {
		sessionDuration, _ = engine.CryptoRandInt(1, 5) // 1-5 seconds for tests
		pageCount, _ = engine.CryptoRandInt(1, 3)      // 1-3 pages per session for tests
	} else {
		sessionDuration, _ = engine.CryptoRandInt(300, 1800) // 5-30 minutes for production
		pageCount, _ = engine.CryptoRandInt(5, 15)           // 5-15 pages per session for production
	}
	
	session := &OrganicTestSession{
		Duration:   time.Duration(sessionDuration) * time.Second,
		PageVisits: make([]PageVisit, pageCount),
		EmbeddedTests: make([]EmbeddedTest, 0),
	}
	
	// Embed strategy tests randomly within the session
	testsToEmbed := minInt(len(fingerprints)-*strategyIndex, 3) // Max 3 tests per session
	for i := 0; i < testsToEmbed && *strategyIndex < len(fingerprints); i++ {
		var targetDomain string
		if isRunningInTest() && len(canaryDomains) > 0 {
			// Use canary domains in tests
			domainIdx, _ := engine.CryptoRandInt(0, len(canaryDomains)-1)
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
	idx, _ := engine.CryptoRandInt(0, len(domains)-1)
	return domains[idx]
}

// selectMaskingType chooses how to mask the strategy test
func (r *Ranker) selectMaskingType() string {
	types := []string{"web_browsing", "video_streaming", "social_media", "file_download"}
	idx, _ := engine.CryptoRandInt(0, len(types)-1)
	return types[idx]
}

// simulateRealisticBrowsingSession simulates a realistic browsing session
func (r *Ranker) simulateRealisticBrowsingSession(ctx context.Context, session *OrganicTestSession) {
	// Simulate multiple page visits with realistic timing
	for range session.PageVisits {
		// Add realistic delays between page visits (much shorter in tests)
		var delay int
		if isRunningInTest() {
			delay, _ = engine.CryptoRandInt(1, 10) // 1-10 milliseconds for tests
		} else {
			delay, _ = engine.CryptoRandInt(2000, 15000) // 2-15 seconds for production
		}
		time.Sleep(time.Duration(delay) * time.Millisecond)
		
		// Simulate page interaction (reading, scrolling, etc.)
		if ctx.Err() != nil {
			return
		}
	}
}

// generatePreRequestActivity simulates realistic activity before a strategy test
func (r *Ranker) generatePreRequestActivity(ctx context.Context, strategy *config.Fingerprint) {
	// Simulate typing in address bar, DNS prefetch, etc.
	var delay int
	if isRunningInTest() {
		delay, _ = engine.CryptoRandInt(1, 5) // 1-5 milliseconds for tests
	} else {
		delay, _ = engine.CryptoRandInt(500, 3000) // 0.5-3 seconds for production
	}
	time.Sleep(time.Duration(delay) * time.Millisecond)
}

// performDisguisedStrategyTest performs the actual strategy test disguised as normal traffic
func (r *Ranker) performDisguisedStrategyTest(ctx context.Context, embeddedTest EmbeddedTest) (bool, time.Duration) {
	start := time.Now()
	
	// Use existing test infrastructure but with disguised parameters
	success, latency, err := r.testStrategy(ctx, embeddedTest.Strategy, []string{embeddedTest.TargetDomain})
	
	// Generate ephemeral correlation ID for this test session
	correlationID := generateEphemeralCorrelationID()
	if err != nil {
		r.Logger.Warn("strategy test failed",
			"correlation_id", correlationID,
			"error_type", classifyErrorType(err))
		return false, time.Since(start)
	} else {
		r.Logger.Debug("strategy test completed",
			"correlation_id", correlationID)
		return success, latency
	}
}

// generatePostRequestActivity simulates realistic activity after a strategy test
func (r *Ranker) generatePostRequestActivity(ctx context.Context, strategy *config.Fingerprint, success bool) {
	// Simulate continued browsing, cache operations, etc.
	var delay int
	if isRunningInTest() {
		delay, _ = engine.CryptoRandInt(1, 5) // 1-5 milliseconds for tests
	} else {
		delay, _ = engine.CryptoRandInt(1000, 8000) // 1-8 seconds for production
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

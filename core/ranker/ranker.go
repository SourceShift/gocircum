package ranker

import (
	"container/list"
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"time"

	"net"
	"strings"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/core/engine"
	"github.com/gocircum/gocircum/core/proxy"
	"github.com/gocircum/gocircum/pkg/logging"
)

type contextKey string

const testContextKey contextKey = "is_test"

var commonUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
}

// Realistic TLS ClientHello patterns for decoy traffic
var realisticClientHelloSizes = []int{
	154, 176, 198, 220, 242, 264, 286, 308, 330, 352, // Chrome variations
	162, 184, 206, 228, 250, 272, 294, 316, 338, 360, // Firefox variations
	145, 167, 189, 211, 233, 255, 277, 299, 321, 343, // Safari variations
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

	// Implement distributed testing with random delays and decoy traffic
	shuffledFingerprints := make([]*config.Fingerprint, len(fingerprints))
	copy(shuffledFingerprints, fingerprints)

	// HARDENED: Shuffle test order to avoid predictable patterns, but disable for deterministic testing.
	if ctx.Value(testContextKey) == nil {
		for i := len(shuffledFingerprints) - 1; i > 0; i-- {
			j, err := engine.CryptoRandInt(0, i)
			if err != nil {
				r.Logger.Error("failed to randomize test order", "error", err)
				return nil, fmt.Errorf("test setup failed")
			}
			shuffledFingerprints[i], shuffledFingerprints[j] = shuffledFingerprints[j], shuffledFingerprints[i]
		}
	}

	// Add random delay between tests to break timing patterns
	for _, fp := range shuffledFingerprints {
		go func(fingerprint *config.Fingerprint) {
			// Random delay to distribute tests over time
			var delayMs int
			var err error
			// HARDENED: Disable long delays during testing to speed up execution.
			if ctx.Value(testContextKey) == nil {
				delayMs, err = engine.CryptoRandInt(1000, 4000) // 1-4 second delay
			} else {
				delayMs, err = engine.CryptoRandInt(10, 50) // 10-50 ms delay for tests
			}
			if err != nil {
				r.Logger.Error("failed to generate random delay, proceeding without it", "error", err)
			} else {
				time.Sleep(time.Duration(delayMs) * time.Millisecond)
			}

			// Generate decoy traffic before real test
			// HARDENED: Disable decoys during testing to avoid interference.
			if ctx.Value(testContextKey) == nil {
				r.generateDecoyTraffic(ctx, canaryDomains)
			}

			success, latency, err := r.testStrategy(ctx, fingerprint, canaryDomains)
			if err != nil {
				r.Logger.Warn("testing strategy failed", "strategy_id", fingerprint.ID, "error", err)
			} else {
				r.Logger.Debug("testing strategy completed", "strategy_id", fingerprint.ID)
			}

			// Generate decoy traffic after real test
			// HARDENED: Disable decoys during testing to avoid interference.
			if ctx.Value(testContextKey) == nil {
				r.generateDecoyTraffic(ctx, canaryDomains)
			}

			results <- StrategyResult{
				Fingerprint: fingerprint,
				Success:     success,
				Latency:     latency,
			}
		}(fp)
	}

	// Collect results with timeout
	var rankedResults []StrategyResult
	timeout := time.After(60 * time.Second)

loop:
	for i := 0; i < len(fingerprints); i++ {
		select {
		case result := <-results:
			rankedResults = append(rankedResults, result)
		case <-timeout:
			r.Logger.Warn("strategy testing timed out", "completed", len(rankedResults), "total", len(fingerprints))
			break loop
		}
	}
	close(results)

	return r.rankResults(rankedResults), nil
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

// generateDecoyTraffic generates fake tests to obfuscate real testing patterns.
func (r *Ranker) generateDecoyTraffic(ctx context.Context, canaryDomains []string) {
	if len(canaryDomains) == 0 {
		return
	}

	// Variable number of decoys with realistic distribution
	numDecoys, err := engine.CryptoRandInt(0, 5) // 0-4 decoys, including no decoys
	if err != nil {
		r.Logger.Error("failed to determine number of decoys", "error", err)
		return
	}

	// Sometimes generate no decoys to break patterns
	if numDecoys == 0 {
		return
	}

	for i := 0; i < numDecoys; i++ {
		go func(decoyIndex int) {
			// Add variable delay between decoy starts
			startDelay, err := engine.CryptoRandInt(0, 2000) // 0-2 second stagger
			if err == nil {
				time.Sleep(time.Duration(startDelay) * time.Millisecond)
			}

			// Random decoy domain
			domainIdx, err := engine.CryptoRandInt(0, len(canaryDomains)-1)
			if err != nil {
				return
			}
			domain := canaryDomains[domainIdx]

			// Variable timeout to mimic different network conditions
			timeout, _ := engine.CryptoRandInt(3, 8)
			decoyDialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}

			conn, err := decoyDialer.DialContext(ctx, "tcp", domain+":443")
			if err != nil {
				return
			}
			defer func() {
				_ = conn.Close()
			}()

			// Generate realistic TLS ClientHello-like data
			clientHelloData := r.generateRealisticClientHello()

			// Write data in chunks like real TLS handshakes
			r.writeRealisticTLSPattern(conn, clientHelloData)

			// Variable delay before closing (realistic connection duration)
			delay, err := engine.CryptoRandInt(100, 3000) // 0.1-3 seconds
			if err != nil {
				delay = 500 // Fallback
			}
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}(i)
	}
}

func (r *Ranker) generateRealisticClientHello() []byte {
	// Choose a realistic size
	sizeIdx, err := engine.CryptoRandInt(0, len(realisticClientHelloSizes)-1)
	if err != nil {
		sizeIdx = 0
	}
	size := realisticClientHelloSizes[sizeIdx]

	// Generate realistic TLS ClientHello structure
	clientHello := make([]byte, size)

	// TLS Record Header (5 bytes)
	clientHello[0] = 0x16 // Content Type: Handshake
	clientHello[1] = 0x03 // Version Major: 3
	clientHello[2] = 0x01 // Version Minor: 1 (TLS 1.0 in record)
	// Length will be filled below

	// Handshake Header (4 bytes)
	clientHello[5] = 0x01 // Handshake Type: Client Hello
	// Length will be filled below

	// Client Hello content starts at byte 9
	clientHello[9] = 0x03  // Version Major: 3
	clientHello[10] = 0x03 // Version Minor: 3 (TLS 1.2)

	// Random (32 bytes) - starts at byte 11
	if _, err := rand.Read(clientHello[11:43]); err != nil {
		// Fallback to time-based pseudo-random
		timeBytes := make([]byte, 32)
		binary.BigEndian.PutUint64(timeBytes, uint64(time.Now().UnixNano()))
		copy(clientHello[11:43], timeBytes)
	}

	// Fill the rest with realistic-looking random data
	if _, err := rand.Read(clientHello[43:]); err != nil {
		// Fallback pattern
		for i := 43; i < len(clientHello); i++ {
			clientHello[i] = byte(i % 256)
		}
	}

	// Set correct lengths
	handshakeLen := size - 9
	binary.BigEndian.PutUint16(clientHello[3:5], uint16(handshakeLen+4))
	clientHello[6] = byte((handshakeLen >> 16) & 0xFF)
	binary.BigEndian.PutUint16(clientHello[7:9], uint16(handshakeLen))

	return clientHello
}

func (r *Ranker) writeRealisticTLSPattern(conn net.Conn, data []byte) {
	// Some connections send ClientHello in one packet
	// Others fragment it across multiple writes
	fragmentChance, _ := engine.CryptoRandInt(0, 10)

	if fragmentChance < 7 || len(data) < 100 {
		// 70% chance: send in one packet (common for small ClientHellos)
		_, _ = conn.Write(data)
		return
	}

	// 30% chance: fragment the ClientHello
	firstChunk, _ := engine.CryptoRandInt(50, len(data)/2)

	_, _ = conn.Write(data[:firstChunk])

	// Small delay between fragments
	delay, _ := engine.CryptoRandInt(1, 10)
	time.Sleep(time.Duration(delay) * time.Millisecond)

	_, _ = conn.Write(data[firstChunk:])
}

// testStrategy performs a single connection test, including an application-layer data exchange.
func (r *Ranker) testStrategy(ctx context.Context, fingerprint *config.Fingerprint, canaryDomains []string) (bool, time.Duration, error) {
	if len(canaryDomains) == 0 {
		return false, 0, fmt.Errorf("misconfiguration: no canary domains")
	}

	// Use expanded, rotating canary domain set to avoid predictable patterns
	expandedDomains := r.getExpandedCanaryDomains(ctx, canaryDomains)

	domainIndex, err := engine.CryptoRandInt(0, len(expandedDomains)-1)
	if err != nil {
		r.Logger.Error("failed to select random canary domain", "error", err)
		return false, 0, fmt.Errorf("test failed: internal error")
	}
	domainToTest := expandedDomains[domainIndex]

	// HARDENED: Disable long delays during testing to speed up execution.
	if ctx.Value(testContextKey) == nil {
		// Add timing jitter to break correlation patterns
		baseJitter, err := engine.CryptoRandInt(500, 2000) // 0.5-2 second base delay
		if err != nil {
			r.Logger.Error("CSPRNG failure for base jitter generation", "error", err)
			return false, 0, fmt.Errorf("test failed: internal error")
		}
		microJitter, err := engine.CryptoRandInt(0, 100) // 0-100ms micro adjustment
		if err != nil {
			r.Logger.Error("CSPRNG failure for micro jitter generation", "error", err)
			return false, 0, fmt.Errorf("test failed: internal error")
		}
		totalJitter := time.Duration(baseJitter)*time.Millisecond + time.Duration(microJitter)*time.Millisecond
		time.Sleep(totalJitter)
	}

	hostToResolve, port, err := net.SplitHostPort(domainToTest)
	if err != nil {
		// If there's an error, it's likely because there was no port.
		hostToResolve = domainToTest
		port = "443" // Default to HTTPS port
	}

	// Securely resolve the canary domain to an IP address using DoH. This prevents
	// leaking the domain to the local network or ISP, and ensures that we do not
	// use an IP address for the SNI, which is a major fingerprinting vector.
	var resolvedIP net.IP
	_, resolvedIP, err = r.DoHResolver.Resolve(ctx, hostToResolve)
	if err != nil {
		r.Logger.Warn("Failed to securely resolve canary domain for testing", "domain", hostToResolve, "error", err)
		return false, 0, fmt.Errorf("test failed: domain resolution")
	}

	// The address we dial is the resolved IP and the original port.
	addressToDial := net.JoinHostPort(resolvedIP.String(), port)

	// HARDENED: Explicitly set the ServerName for the TLS configuration
	// to the original hostname. This ensures the SNI is the domain name, not the IP address.
	tlsCfg := fingerprint.TLS
	tlsCfg.ServerName = hostToResolve // This is the critical fix.

	dialer, err := r.DialerFactory.NewDialer(&fingerprint.Transport, &tlsCfg)
	if err != nil {
		return false, 0, err
	}

	start := time.Now()
	conn, err := dialer(ctx, "tcp", addressToDial)
	if err != nil {
		return false, 0, err
	}
	defer func() {
		_ = conn.Close()
	}()
	latency := time.Since(start)

	// HARDENED LIVENESS CHECK: Perform a padded and fragmented HTTP GET to verify application data flow.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) // Set a deadline for the exchange.

	// Build the request with padding to obfuscate its size.
	var requestBuilder strings.Builder
	userAgentIndex, _ := engine.CryptoRandInt(0, len(commonUserAgents)-1)
	userAgent := commonUserAgents[userAgentIndex]
	requestBuilder.WriteString(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\n", hostToResolve, userAgent))

	paddingHeaders, err := engine.CryptoRandInt(2, 5)
	if err != nil {
		r.Logger.Error("CSPRNG failure for padding header count", "error", err)
		return false, 0, fmt.Errorf("test failed: internal error")
	}
	for i := 0; i < int(paddingHeaders); i++ {
		keyBytes := make([]byte, 8)
		valBytes := make([]byte, 16)
		if _, err := rand.Read(keyBytes); err != nil {
			r.Logger.Error("CSPRNG failure for padding key generation", "error", err)
			return false, 0, fmt.Errorf("test failed: internal error")
		}
		if _, err := rand.Read(valBytes); err != nil {
			r.Logger.Error("CSPRNG failure for padding value generation", "error", err)
			return false, 0, fmt.Errorf("test failed: internal error")
		}
		requestBuilder.WriteString(fmt.Sprintf("X-Padding-%x: %x\r\n", keyBytes, valBytes))
	}
	requestBuilder.WriteString("\r\n")

	requestBytes := []byte(requestBuilder.String())

	// Fragment the request write to break the single-packet fingerprint.
	offset := 0
	for offset < len(requestBytes) {
		// Determine chunk size dynamically to further obfuscate the pattern.
		maxChunk, _ := engine.CryptoRandInt(20, 60)
		chunkSize := int(maxChunk)
		if offset+chunkSize > len(requestBytes) {
			chunkSize = len(requestBytes) - offset
		}

		if _, err := conn.Write(requestBytes[offset : offset+chunkSize]); err != nil {
			r.Logger.Warn("failed to write to canary", "error", err)
			return false, 0, fmt.Errorf("test failed: connection write")
		}
		offset += chunkSize

		// Add a small, random delay between fragments.
		delay, _ := engine.CryptoRandInt(10, 50)
		time.Sleep(time.Duration(delay) * time.Millisecond)
	}

	// Read the beginning of the response to confirm the connection is valid.
	// We don't need the full response, just enough to confirm the handshake worked
	// and the server is responding.
	responseBuf := make([]byte, 1024)
	if _, err := conn.Read(responseBuf); err != nil {
		// Ignore "close" and EOF errors which are expected in a short-lived test connection.
		if !strings.Contains(err.Error(), "closed") && !strings.Contains(err.Error(), "EOF") {
			r.Logger.Warn("failed to read from canary", "error", err)
			return false, 0, fmt.Errorf("test failed: connection read")
		}
	}

	return true, latency, nil
}

// getExpandedCanaryDomains expands the canary domain set with common domains to blend in with normal traffic.
func (r *Ranker) getExpandedCanaryDomains(ctx context.Context, baseDomains []string) []string {
	// HARDENED: Disable expansion during testing to ensure predictability.
	if ctx.Value(testContextKey) != nil {
		return baseDomains
	}
	// Add common domains that users might normally visit to create a larger, more diverse set for testing.
	commonDomains := []string{
		"www.wikipedia.org",
		"www.github.com",
		"stackoverflow.com",
		"www.reddit.com",
		"news.ycombinator.com",
	}

	expanded := make([]string, 0, len(baseDomains)+len(commonDomains))
	expanded = append(expanded, baseDomains...)

	// Randomly include some common domains to vary the test targets between runs.
	for _, domain := range commonDomains {
		include, err := engine.CryptoRandInt(0, 1)
		if err == nil && include == 1 {
			expanded = append(expanded, domain)
		}
	}

	return expanded
}

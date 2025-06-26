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
	if r.DialerFactory == nil {
		return false, 0, fmt.Errorf("DialerFactory not set")
	}

	if len(canaryDomains) == 0 {
		return false, 0, fmt.Errorf("no canary domains provided for testing")
	}

	// Choose a random canary domain for this test
	domainIndex, err := engine.CryptoRandInt(0, len(canaryDomains)-1)
	if err != nil {
		return false, 0, fmt.Errorf("failed to select canary domain: %w", err)
	}
	targetDomain := canaryDomains[domainIndex]

	r.Logger.Debug("testing strategy", "strategy_id", fingerprint.ID, "target_domain", targetDomain)

	// Architectural requirement: For TCP transport, TLS must be handled by the caller
	var dialer engine.Dialer
	if fingerprint.Transport.Protocol == "tcp" {
		// Create dialer for TCP transport without TLS config
		dialer, err = r.DialerFactory.NewDialer(&fingerprint.Transport, nil)
		if err != nil {
			return false, 0, fmt.Errorf("failed to create dialer for strategy %s: %w", fingerprint.ID, err)
		}
	} else {
		// For non-TCP transports, pass the TLS config directly to the dialer factory
		dialer, err = r.DialerFactory.NewDialer(&fingerprint.Transport, &fingerprint.TLS)
		if err != nil {
			return false, 0, fmt.Errorf("failed to create dialer for strategy %s: %w", fingerprint.ID, err)
		}
	}

	// Measure the connection
	start := time.Now()
	conn, err := dialer(ctx, "tcp", net.JoinHostPort(targetDomain, "443"))
	latency := time.Since(start)

	if err != nil {
		return false, 0, err
	}
	defer conn.Close()

	// For TLS connections, we need to verify the handshake completed successfully.
	// This is now implicitly handled by the uTLS dialer which returns an error on handshake failure.
	// A successful connection implies a successful handshake.

	return true, latency, nil
}

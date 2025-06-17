package ranker

import (
	"container/list"
	"context"
	"crypto/rand"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/engine"
	"gocircum/core/proxy"
	"gocircum/pkg/logging"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

var commonUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:107.0) Gecko/20100101 Firefox/107.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15",
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
		return nil, fmt.Errorf("failed to initialize DoH resolver for ranker: %w", err)
	}
	return &Ranker{
		ActiveProbes:  list.New(),
		Logger:        logger,
		Cache:         make(map[string]*CacheEntry),
		DialerFactory: &engine.DefaultDialerFactory{},
		DoHResolver:   dohResolver,
	}, nil
}

// TestAndRank sorts fingerprints by success and latency.
func (r *Ranker) TestAndRank(ctx context.Context, fingerprints []*config.Fingerprint, canaryDomains []string) ([]StrategyResult, error) {
	results := make(chan StrategyResult, len(fingerprints))
	for _, fp := range fingerprints {
		go func(fingerprint *config.Fingerprint) {
			// Check cache first
			r.CacheLock.RLock()
			entry, found := r.Cache[fingerprint.ID]
			r.CacheLock.RUnlock()

			if found && time.Since(entry.Timestamp) < 5*time.Minute { // 5-minute cache validity
				r.Logger.Debug("cache hit", "strategy_id", fingerprint.ID)
				results <- StrategyResult{
					Fingerprint: fingerprint,
					Success:     true,
					Latency:     entry.Latency,
				}
				return
			}
			r.Logger.Debug("cache miss", "strategy_id", fingerprint.ID)
			success, latency, err := r.testStrategy(ctx, fingerprint, canaryDomains)
			if err != nil {
				r.Logger.Warn("testing strategy failed", "strategy_id", fingerprint.ID, "error", err)
			}

			if success {
				// Update cache
				r.CacheLock.Lock()
				r.Cache[fingerprint.ID] = &CacheEntry{
					FingerprintID: fingerprint.ID,
					Latency:       latency,
					Timestamp:     time.Now(),
				}
				r.CacheLock.Unlock()
			}

			results <- StrategyResult{
				Fingerprint: fingerprint,
				Success:     success,
				Latency:     latency,
			}
		}(fp)
	}

	var rankedResults []StrategyResult
	for i := 0; i < len(fingerprints); i++ {
		rankedResults = append(rankedResults, <-results)
	}
	close(results)

	sort.Slice(rankedResults, func(i, j int) bool {
		if rankedResults[i].Success != rankedResults[j].Success {
			return rankedResults[i].Success // true comes before false
		}
		if !rankedResults[i].Success {
			return false // Order of failures doesn't matter
		}
		return rankedResults[i].Latency < rankedResults[j].Latency
	})

	return rankedResults, nil
}

// testStrategy performs a single connection test, including an application-layer data exchange.
func (r *Ranker) testStrategy(ctx context.Context, fingerprint *config.Fingerprint, canaryDomains []string) (bool, time.Duration, error) {
	if len(canaryDomains) == 0 {
		return false, 0, fmt.Errorf("no canary domains provided")
	}

	domainIndex, err := engine.CryptoRandInt(0, len(canaryDomains)-1)
	if err != nil {
		return false, 0, fmt.Errorf("failed to select random canary domain: %w", err)
	}
	domainToTest := canaryDomains[domainIndex]
	hostToResolve, port, err := net.SplitHostPort(domainToTest)
	if err != nil {
		// If there's an error, it's likely because there was no port.
		hostToResolve = domainToTest
		port = "443" // Default to HTTPS port
	}

	var resolvedIP net.IP
	// If the host is already an IP, no need to resolve it.
	parsedIP := net.ParseIP(hostToResolve)
	if parsedIP != nil {
		resolvedIP = parsedIP
	} else {
		// Use the DoHResolver to resolve the canary domain securely.
		_, resolvedIP, err = r.DoHResolver.Resolve(ctx, hostToResolve)
		if err != nil {
			r.Logger.Warn("Failed to securely resolve canary domain for testing", "domain", hostToResolve, "error", err)
			return false, 0, fmt.Errorf("failed to securely resolve canary domain '%s': %w", hostToResolve, err)
		}
	}

	addressToDial := net.JoinHostPort(resolvedIP.String(), port)

	// CRITICAL FIX: Explicitly set the ServerName for the TLS configuration
	// to the original hostname. This ensures the SNI is the domain name, not the IP address.
	tlsCfg := fingerprint.TLS
	tlsCfg.ServerName = hostToResolve

	dialer, err := r.DialerFactory.NewDialer(&fingerprint.Transport, &tlsCfg)
	if err != nil {
		return false, 0, err
	}

	jitterMs, err := engine.CryptoRandInt(50, 250)
	if err != nil {
		r.Logger.Error("failed to generate secure jitter", "error", err)
		jitterMs = 100
	}
	time.Sleep(time.Duration(jitterMs) * time.Millisecond)

	start := time.Now()
	conn, err := dialer(ctx, "tcp", addressToDial)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	latency := time.Since(start)

	// HARDENED LIVENESS CHECK: Perform a padded and fragmented HTTP GET to verify application data flow.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second)) // Set a deadline for the exchange.

	// Build the request with padding to obfuscate its size.
	var requestBuilder strings.Builder
	userAgentIndex, _ := engine.CryptoRandInt(0, len(commonUserAgents)-1)
	userAgent := commonUserAgents[userAgentIndex]
	requestBuilder.WriteString(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: %s\r\n", hostToResolve, userAgent))

	paddingHeaders, _ := engine.CryptoRandInt(2, 5)
	for i := 0; i < int(paddingHeaders); i++ {
		keyBytes := make([]byte, 8)
		valBytes := make([]byte, 16)
		_, _ = rand.Read(keyBytes)
		_, _ = rand.Read(valBytes)
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
			return false, 0, fmt.Errorf("failed to write fragmented GET to canary: %w", err)
		}
		offset += chunkSize

		// Add a small, random delay between fragments.
		if offset < len(requestBytes) {
			delay, _ := engine.CryptoRandInt(10, 30)
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
	}

	// Read the first line of the response to check for a valid HTTP status.
	responseBytes := make([]byte, 1024)
	n, err := conn.Read(responseBytes)
	if err != nil {
		return false, 0, fmt.Errorf("failed to read response from canary: %w", err)
	}

	response := string(responseBytes[:n])
	if !strings.HasPrefix(response, "HTTP/1.") {
		return false, 0, fmt.Errorf("invalid HTTP response from canary: %s", response)
	}

	return true, latency, nil
}

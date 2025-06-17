package ranker

import (
	"container/list"
	"context"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/engine"
	"gocircum/core/proxy"
	"gocircum/pkg/logging"
	"net"
	"sort"
	"sync"
	"time"
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

// testStrategy performs a single connection test.
func (r *Ranker) testStrategy(ctx context.Context, fingerprint *config.Fingerprint, canaryDomains []string) (bool, time.Duration, error) {
	if len(canaryDomains) == 0 {
		return false, 0, fmt.Errorf("no canary domains provided")
	}

	domainIndex, err := engine.CryptoRandInt(0, len(canaryDomains)-1)
	if err != nil {
		return false, 0, fmt.Errorf("failed to select random canary domain: %w", err)
	}
	domainToResolve := canaryDomains[domainIndex]

	// Use the DoHResolver to resolve the canary domain securely.
	// This prevents system DNS leakage.
	_, resolvedIP, err := r.DoHResolver.Resolve(ctx, domainToResolve)
	if err != nil {
		r.Logger.Warn("Failed to securely resolve canary domain for testing", "domain", domainToResolve, "error", err)
		return false, 0, fmt.Errorf("failed to securely resolve canary domain '%s': %w", domainToResolve, err)
	}

	// The address for the dialer must now be IP:port
	addressToDial := resolvedIP.String() + ":443" // Assuming HTTPS default port

	dialer, err := r.DialerFactory.NewDialer(&fingerprint.Transport, &fingerprint.TLS)
	if err != nil {
		return false, 0, err
	}

	// Add cryptographically secure random jitter to break timing patterns
	jitterMs, err := engine.CryptoRandInt(50, 250)
	if err != nil {
		r.Logger.Error("failed to generate secure jitter", "error", err)
		// Fallback to a static jitter, but this should not happen.
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

	// Could add a simple echo test here for verification
	return true, latency, nil
}

package ranker

import (
	"container/list"
	"context"
	"gocircum/core/config"
	"gocircum/core/engine"
	"gocircum/pkg/logging"
	"sort"
	"sync"
	"time"
)

const CanaryDomain = "www.cloudflare.com:443"

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
	ActiveProbes *list.List
	Cache        map[string]*CacheEntry
	CacheLock    sync.RWMutex
	Logger       logging.Logger
}

// NewRanker creates a new Ranker instance.
func NewRanker(logger logging.Logger) *Ranker {
	if logger == nil {
		logger = logging.GetLogger()
	}
	return &Ranker{
		ActiveProbes: list.New(),
		Logger:       logger,
		Cache:        make(map[string]*CacheEntry),
	}
}

// TestAndRank sorts fingerprints by success and latency.
func (r *Ranker) TestAndRank(ctx context.Context, fingerprints []*config.Fingerprint) ([]StrategyResult, error) {
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
			success, latency, err := r.testStrategy(ctx, fingerprint)
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
func (r *Ranker) testStrategy(ctx context.Context, fingerprint *config.Fingerprint) (bool, time.Duration, error) {
	dialer, err := engine.NewDialer(&fingerprint.Transport, &fingerprint.TLS)
	if err != nil {
		return false, 0, err
	}

	start := time.Now()
	conn, err := dialer(ctx, "tcp", CanaryDomain)
	if err != nil {
		return false, 0, err
	}
	defer conn.Close()
	latency := time.Since(start)

	// Could add a simple echo test here for verification
	return true, latency, nil
}

package ranker

import (
	"context"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/engine"
	"sort"
	"time"
)

const CanaryDomain = "www.cloudflare.com:443"

// StrategyResult holds the outcome of testing a single fingerprint.
type StrategyResult struct {
	Fingerprint *config.Fingerprint
	Success     bool
	Latency     time.Duration
}

// Ranker tests and ranks connection strategies.
type Ranker struct {
	// TODO: Add a cache for results to avoid re-testing.
}

// NewRanker creates a new Ranker instance.
func NewRanker() *Ranker {
	return &Ranker{}
}

// TestAndRank sorts fingerprints by success and latency.
func (r *Ranker) TestAndRank(ctx context.Context, fingerprints []*config.Fingerprint) ([]StrategyResult, error) {
	results := make(chan StrategyResult, len(fingerprints))
	for _, fp := range fingerprints {
		go func(fingerprint *config.Fingerprint) {
			success, latency, err := r.testStrategy(ctx, fingerprint)
			if err != nil {
				// TODO: Use a proper logger
				fmt.Printf("testing strategy %s failed: %v\n", fingerprint.ID, err)
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

// testStrategy attempts to connect to the canary domain using a given fingerprint.
func (r *Ranker) testStrategy(ctx context.Context, fingerprint *config.Fingerprint) (bool, time.Duration, error) {
	dialerFunc, err := engine.NewDialer(&fingerprint.Transport)
	if err != nil {
		return false, 0, fmt.Errorf("failed to create dialer: %w", err)
	}

	start := time.Now()

	// Use a context with a timeout for the entire connection process.
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	rawConn, err := dialerFunc(dialCtx, "tcp", CanaryDomain)
	if err != nil {
		return false, 0, fmt.Errorf("transport dial failed: %w", err)
	}
	defer rawConn.Close()

	tlsConn, err := engine.NewTLSClient(rawConn, &fingerprint.TLS)
	if err != nil {
		return false, 0, fmt.Errorf("tls handshake failed: %w", err)
	}
	latency := time.Since(start)
	defer tlsConn.Close()

	return true, latency, nil
}

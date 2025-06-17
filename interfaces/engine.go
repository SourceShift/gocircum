//go:generate mockgen -package=mocks -destination=../mocks/mock_engine.go gocircum/interfaces Engine
package interfaces

import (
	"context"
	"gocircum/core/config"
	"gocircum/core/ranker"
)

// Engine defines the public interface for the circumvention engine.
type Engine interface {
	// Start finds the best strategy and starts a proxy.
	Start(addr string) (string, error)
	// Stop gracefully stops the engine.
	Stop() error
	// Status returns the current operational status of the engine.
	Status() (string, error)
	// TestStrategies tests all available fingerprints and returns the ranked results.
	TestStrategies(ctx context.Context) ([]ranker.StrategyResult, error)
	// GetBestStrategy tests all available strategies and returns the best one.
	GetBestStrategy(ctx context.Context) (*config.Fingerprint, error)
	// GetStrategyByID returns a strategy fingerprint by its ID.
	GetStrategyByID(id string) (*config.Fingerprint, error)
	// StartProxyWithStrategy starts a SOCKS5 proxy using a specific fingerprint.
	StartProxyWithStrategy(ctx context.Context, addr string, fp *config.Fingerprint) (string, error)
}

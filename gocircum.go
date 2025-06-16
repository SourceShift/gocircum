package gocircum

import (
	"context"
	"fmt"
	"gocircum/core"
	"gocircum/core/config"
	"gocircum/core/ranker"
	"gocircum/interfaces"
)

// Engine represents the circumvention engine.
type Engine struct {
	coreEngine *core.Engine
}

// NewEngine creates a new instance of the circumvention engine from a set of fingerprints.
func NewEngine(fingerprints []*config.Fingerprint) (interfaces.Engine, error) {
	coreEngine, err := core.NewEngine(fingerprints)
	if err != nil {
		return nil, err
	}
	return &Engine{coreEngine: coreEngine}, nil
}

// Start finds the best strategy and starts a proxy.
func (e *Engine) Start(addr string) error {
	best, err := e.GetBestStrategy(context.Background())
	if err != nil {
		return fmt.Errorf("could not get best strategy: %w", err)
	}
	return e.StartProxyWithStrategy(context.Background(), addr, best)
}

// StartProxyWithStrategy starts a SOCKS5 proxy using a specific fingerprint.
func (e *Engine) StartProxyWithStrategy(ctx context.Context, addr string, fp *config.Fingerprint) error {
	return e.coreEngine.StartProxyWithStrategy(ctx, addr, fp)
}

// Stop gracefully stops the engine.
func (e *Engine) Stop() error {
	return e.coreEngine.Stop()
}

// Status returns the current operational status of the engine.
func (e *Engine) Status() (string, error) {
	return e.coreEngine.Status()
}

// TestStrategies tests all available fingerprints and returns the ranked results.
func (e *Engine) TestStrategies(ctx context.Context) ([]ranker.StrategyResult, error) {
	return e.coreEngine.TestStrategies(ctx)
}

// GetBestStrategy tests all available strategies and returns the best one.
func (e *Engine) GetBestStrategy(ctx context.Context) (*config.Fingerprint, error) {
	return e.coreEngine.GetBestStrategy(ctx)
}

// GetStrategyByID returns a strategy fingerprint by its ID.
func (e *Engine) GetStrategyByID(id string) (*config.Fingerprint, error) {
	return e.coreEngine.GetStrategyByID(id)
}

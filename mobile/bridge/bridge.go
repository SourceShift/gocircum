// Package bridge provides a gomobile-compatible wrapper around the core gocircum library.
package bridge

import (
	"context"
	"fmt"
	"gocircum"
	"gocircum/core/config"
	"gocircum/interfaces"
	"gocircum/pkg/logging"
	"sync"

	"gopkg.in/yaml.v3"
)

// Bridge manages the lifecycle of the gocircum engine in a thread-safe manner.
type Bridge struct {
	mu     sync.Mutex
	wg     sync.WaitGroup
	engine interfaces.Engine
	cancel context.CancelFunc
}

// NewBridge creates a new Bridge instance.
func NewBridge() *Bridge {
	return &Bridge{}
}

var (
	// globalBridge is a single, global instance of the Bridge.
	// This is a common pattern for gomobile to provide stable C-style function entry points.
	globalBridge = NewBridge()
)

// StatusUpdater is an interface that native mobile code must implement
// to receive status updates from the Go library.
type StatusUpdater interface {
	// OnStatusUpdate is called with a status string (e.g., "CONNECTED", "DISCONNECTED")
	// and a descriptive message.
	OnStatusUpdate(status, message string)
}

// StartEngine initializes and starts the circumvention engine.
// It is the entry point for mobile applications.
func StartEngine(configJSON string, updater StatusUpdater) {
	if err := globalBridge.start(configJSON, updater); err != nil {
		updater.OnStatusUpdate("ERROR", err.Error())
	}
}

// StopEngine stops the circumvention engine and the proxy.
// It is the entry point for mobile applications.
func StopEngine(updater StatusUpdater) {
	if err := globalBridge.stop(); err != nil {
		updater.OnStatusUpdate("ERROR", err.Error())
	} else {
		updater.OnStatusUpdate("DISCONNECTED", "Engine stopped.")
	}
}

// start initializes and starts the circumvention engine.
// It finds the best strategy and starts a SOCKS5 proxy.
func (b *Bridge) start(configJSON string, updater StatusUpdater) error {
	logger := logging.GetLogger().With("component", "bridge")
	logger.Info("StartEngine called")

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.engine != nil {
		return fmt.Errorf("engine already started")
	}

	updater.OnStatusUpdate("CONNECTING", "Loading configuration...")

	if configJSON == "" {
		// As per subtask 19.3, handle empty configuration.
		// For now, we return an error. A future task could implement default strategies.
		return fmt.Errorf("configuration is empty; please provide at least one strategy")
	}

	var cfg config.FileConfig
	// Use yaml.Unmarshal as it can handle JSON, which is a subset of YAML.
	if err := yaml.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Errorf("failed to parse configuration: %w", err)
	}
	if len(cfg.Fingerprints) == 0 {
		return fmt.Errorf("no strategies found in the provided configuration")
	}

	var err error
	engine, err := gocircum.NewEngine(cfg.Fingerprints, logger)
	if err != nil {
		return fmt.Errorf("failed to create engine: %w", err)
	}
	b.engine = engine

	updater.OnStatusUpdate("CONNECTING", "Finding the best strategy...")

	results, err := b.engine.TestStrategies(context.Background())
	if err != nil {
		b.engine = nil // Reset engine state
		return fmt.Errorf("failed to test strategies: %w", err)
	}

	var bestStrategy *config.Fingerprint
	for _, res := range results {
		if res.Success {
			bestStrategy = res.Fingerprint
			break
		}
	}

	if bestStrategy == nil {
		b.engine = nil // Reset engine state
		return fmt.Errorf("no working strategies found")
	}

	updater.OnStatusUpdate("CONNECTING", "Starting proxy with strategy: "+bestStrategy.Description)

	var ctx context.Context
	ctx, b.cancel = context.WithCancel(context.Background())

	addr := "127.0.0.1:1080"
	if cfg.Proxy != nil && cfg.Proxy.ListenAddr != "" {
		addr = cfg.Proxy.ListenAddr
	}

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		logger.Info("Starting SOCKS5 proxy", "address", addr)
		err := b.engine.StartProxyWithStrategy(ctx, addr, bestStrategy)
		if err != nil {
			logger.Error("Proxy stopped with error", "error", err)
			// This error is expected on graceful shutdown, so we check the context.
			if ctx.Err() == nil {
				updater.OnStatusUpdate("DISCONNECTED", "Proxy failed: "+err.Error())
			}
		}
	}()

	updater.OnStatusUpdate("CONNECTED", "Proxy is running on "+addr)
	return nil
}

// stop stops the circumvention engine and the proxy.
func (b *Bridge) stop() error {
	logger := logging.GetLogger().With("component", "bridge")
	logger.Info("StopEngine called")

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.engine == nil {
		return fmt.Errorf("engine not running")
	}

	if b.cancel != nil {
		b.cancel()
	}

	b.wg.Wait() // Wait for the proxy goroutine to finish.

	b.engine = nil
	b.cancel = nil

	return nil
}

// SetGlobalBridgeForTesting replaces the global bridge instance with a new one.
// This is intended for testing purposes only to reset state between tests.
// If b is nil, it resets to a new default bridge.
func SetGlobalBridgeForTesting(b *Bridge) {
	if b == nil {
		globalBridge = NewBridge()
		return
	}
	globalBridge = b
}

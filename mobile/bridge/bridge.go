// Package bridge provides a gomobile-compatible wrapper around the core gocircum library.
package bridge

import (
	"context"
	"gocircum/core"
	"gocircum/core/config"
	"log"
	// TODO: Need a way to load configs. For now, they are hardcoded.
)

var (
	// engine is a single, global instance of the core engine.
	engine *core.Engine
	// cancel is a function to stop the running proxy.
	cancel context.CancelFunc
)

// StatusUpdater is an interface that native mobile code must implement
// to receive status updates from the Go library.
type StatusUpdater interface {
	// OnStatusUpdate is called with a status string (e.g., "CONNECTED", "DISCONNECTED")
	// and a descriptive message.
	OnStatusUpdate(status, message string)
}

// StartEngine initializes and starts the circumvention engine.
// It finds the best strategy and starts a SOCKS5 proxy.
// configJSON is a placeholder for future use.
func StartEngine(configJSON string, updater StatusUpdater) {
	if engine != nil {
		updater.OnStatusUpdate("ERROR", "Engine already started")
		return
	}

	var err error
	engine, err = core.NewEngine()
	if err != nil {
		updater.OnStatusUpdate("ERROR", "Failed to create engine: "+err.Error())
		return
	}

	updater.OnStatusUpdate("CONNECTING", "Finding the best strategy...")

	// TODO: Load fingerprints from configJSON instead of hardcoding.
	fingerprints := []*config.Fingerprint{
		{
			ID:          "default_tcp_stdlib",
			Description: "Default TCP with stdlib TLS 1.3",
			Transport:   config.Transport{Protocol: "tcp"},
			TLS:         config.TLS{Library: "stdlib", MinVersion: "1.3", MaxVersion: "1.3"},
		},
		{
			ID:          "default_tcp_utls_chrome",
			Description: "Default TCP with uTLS Chrome",
			Transport:   config.Transport{Protocol: "tcp"},
			TLS:         config.TLS{Library: "utls", ClientHelloID: "HelloChrome_Auto", MinVersion: "1.3", MaxVersion: "1.3"},
		},
	}

	results, err := engine.TestStrategies(context.Background(), fingerprints)
	if err != nil {
		updater.OnStatusUpdate("ERROR", "Failed to test strategies: "+err.Error())
		return
	}

	var bestStrategy *config.Fingerprint
	for _, res := range results {
		if res.Success {
			bestStrategy = res.Fingerprint
			break
		}
	}

	if bestStrategy == nil {
		updater.OnStatusUpdate("DISCONNECTED", "No working strategies found.")
		engine = nil // Reset engine state
		return
	}

	updater.OnStatusUpdate("CONNECTING", "Starting proxy with strategy: "+bestStrategy.Description)

	var ctx context.Context
	ctx, cancel = context.WithCancel(context.Background())

	go func() {
		addr := "127.0.0.1:1080"
		err := engine.StartProxyWithStrategy(ctx, addr, bestStrategy)
		if err != nil {
			log.Printf("Proxy stopped with error: %v", err)
			// This error is expected on graceful shutdown, so we check the context.
			if ctx.Err() == nil {
				updater.OnStatusUpdate("DISCONNECTED", "Proxy failed: "+err.Error())
			}
		}
	}()

	updater.OnStatusUpdate("CONNECTED", "Proxy is running on 127.0.0.1:1080")
}

// StopEngine stops the circumvention engine and the proxy.
func StopEngine(updater StatusUpdater) {
	if engine == nil {
		updater.OnStatusUpdate("ERROR", "Engine not running")
		return
	}

	if cancel != nil {
		cancel()
	}

	engine = nil
	cancel = nil

	updater.OnStatusUpdate("DISCONNECTED", "Engine stopped.")
}

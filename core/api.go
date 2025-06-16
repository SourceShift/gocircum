package core

import (
	"context"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/engine"
	"gocircum/core/proxy"
	"gocircum/core/ranker"
	"net"
	"sync"
)

// Engine is the main controller for the circumvention library.
type Engine struct {
	ranker       *ranker.Ranker
	fingerprints []*config.Fingerprint
	activeProxy  *proxy.Proxy
	proxyErr     error
	mu           sync.Mutex
	// TODO: Add fields for fingerprints, active proxy, etc.
}

// NewEngine creates a new core engine with a given set of fingerprints.
func NewEngine(fingerprints []*config.Fingerprint) (*Engine, error) {
	if len(fingerprints) == 0 {
		return nil, fmt.Errorf("engine must be initialized with at least one fingerprint")
	}
	return &Engine{
		ranker:       ranker.NewRanker(),
		fingerprints: fingerprints,
	}, nil
}

// Start starts the proxy with a default strategy and address.
// It is a non-blocking call.
func (e *Engine) Start() error {
	addr := "127.0.0.1:1080" // Default address
	fp := &config.Fingerprint{
		ID:          "default_placeholder",
		Description: "Default TCP with stdlib TLS 1.3",
		Transport: config.Transport{
			Protocol: "tcp",
		},
		TLS: config.TLS{
			Library:    "stdlib",
			MinVersion: "1.3",
			MaxVersion: "1.3",
		},
	}
	return e.StartProxyWithStrategy(context.Background(), addr, fp)
}

// Stop gracefully stops the running proxy.
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeProxy == nil {
		return fmt.Errorf("proxy is not running")
	}

	err := e.activeProxy.Stop()
	e.activeProxy = nil // Signal graceful shutdown
	return err
}

// Status returns the current status of the proxy.
func (e *Engine) Status() (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.proxyErr != nil {
		err := e.proxyErr
		e.proxyErr = nil // Clear error after reporting
		return fmt.Sprintf("Proxy failed: %v", err), err
	}
	if e.activeProxy != nil {
		return fmt.Sprintf("Proxy running on %s", e.activeProxy.Addr()), nil
	}
	return "Proxy stopped", nil
}

// TestStrategies tests all available fingerprints and returns the ranked results.
func (e *Engine) TestStrategies(ctx context.Context) ([]ranker.StrategyResult, error) {
	return e.ranker.TestAndRank(ctx, e.fingerprints)
}

// StartProxyWithStrategy starts a SOCKS5 proxy using a specific fingerprint.
// This is a non-blocking call. The proxy runs in a background goroutine.
func (e *Engine) StartProxyWithStrategy(ctx context.Context, addr string, fp *config.Fingerprint) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeProxy != nil {
		return fmt.Errorf("a proxy is already running on %s", e.activeProxy.Addr())
	}

	dialer, err := e.createDialerForStrategy(fp)
	if err != nil {
		return fmt.Errorf("could not create dialer for strategy %s: %w", fp.ID, err)
	}

	p, err := proxy.New(addr, dialer)
	if err != nil {
		return fmt.Errorf("could not create proxy: %w", err)
	}
	e.activeProxy = p
	e.proxyErr = nil

	go func() {
		fmt.Printf("Starting proxy with strategy '%s' on %s\n", fp.Description, p.Addr())
		err := p.Start()

		e.mu.Lock()
		defer e.mu.Unlock()
		// If the proxy was stopped gracefully, err will be non-nil.
		// We should only store the error if it was not a graceful stop.
		// A graceful stop is signaled by setting e.activeProxy to nil.
		if e.activeProxy != nil {
			e.proxyErr = err
		}
	}()

	return nil
}

func (e *Engine) createDialerForStrategy(fp *config.Fingerprint) (proxy.CustomDialer, error) {
	// 1. Create the base dialer (TCP/QUIC with fragmentation)
	baseDialer, err := engine.NewDialer(&fp.Transport)
	if err != nil {
		return nil, err
	}

	// 2. Create the full dialer function that includes the TLS layer
	fullDialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		rawConn, err := baseDialer(ctx, network, address)
		if err != nil {
			return nil, err
		}

		tlsConn, err := engine.NewTLSClient(rawConn, &fp.TLS)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		return tlsConn, nil
	}

	return fullDialer, nil
}

// GetBestStrategy tests all available strategies and returns the best one.
func (e *Engine) GetBestStrategy(ctx context.Context) (*config.Fingerprint, error) {
	results, err := e.ranker.TestAndRank(ctx, e.fingerprints)
	if err != nil {
		return nil, fmt.Errorf("failed to test and rank strategies: %w", err)
	}

	for _, res := range results {
		if res.Success {
			return res.Fingerprint, nil
		}
	}

	return nil, fmt.Errorf("no successful strategy found")
}

// GetStrategyByID returns a strategy fingerprint by its ID.
func (e *Engine) GetStrategyByID(id string) (*config.Fingerprint, error) {
	for _, fp := range e.fingerprints {
		if fp.ID == id {
			return fp, nil
		}
	}
	return nil, fmt.Errorf("strategy with ID '%s' not found", id)
}

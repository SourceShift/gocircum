package core

import (
	"context"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/engine"
	"gocircum/core/proxy"
	"gocircum/core/ranker"
	"gocircum/pkg/logging"
	"net"
	"sync"
)

// Engine is the main controller for the circumvention library.
type Engine struct {
	ranker         *ranker.Ranker
	fingerprints   []config.Fingerprint
	activeProxy    *proxy.Proxy
	mu             sync.Mutex
	proxyErrorChan chan error
	logger         logging.Logger
}

// NewEngine creates a new core engine with a given set of fingerprints.
func NewEngine(fingerprints []config.Fingerprint, logger logging.Logger) (*Engine, error) {
	if len(fingerprints) == 0 {
		return nil, fmt.Errorf("engine must be initialized with at least one fingerprint")
	}
	if logger == nil {
		logger = logging.GetLogger()
	}
	return &Engine{
		ranker:         ranker.NewRanker(logger),
		fingerprints:   fingerprints,
		proxyErrorChan: make(chan error, 1),
		logger:         logger.With("component", "engine"),
	}, nil
}

// Start starts the proxy with a default strategy and address.
// It is a non-blocking call.
func (e *Engine) Start() error {
	return fmt.Errorf("Start is deprecated; use StartProxyWithStrategy with a specific strategy")
}

// Stop gracefully stops the running proxy.
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeProxy == nil {
		return fmt.Errorf("proxy is not running")
	}

	err := e.activeProxy.Stop()
	if err != nil {
		return fmt.Errorf("failed to stop proxy: %w", err)
	}
	e.activeProxy = nil // Signal graceful shutdown
	return nil
}

// Status returns the current status of the proxy.
func (e *Engine) Status() string {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeProxy != nil {
		return fmt.Sprintf("Proxy running on %s", e.activeProxy.Addr())
	}
	return "Proxy stopped"
}

// TestStrategies tests all available fingerprints and returns the ranked results.
func (e *Engine) TestStrategies(ctx context.Context) ([]ranker.StrategyResult, error) {
	e.logger.Info("Testing all strategies...")
	// Convert to slice of pointers for the ranker
	var fps []*config.Fingerprint
	for i := range e.fingerprints {
		fps = append(fps, &e.fingerprints[i])
	}
	results, err := e.ranker.TestAndRank(ctx, fps)
	if err != nil {
		e.logger.Error("Failed to test and rank strategies", "error", err)
	} else {
		e.logger.Info("Finished testing strategies", "num_results", len(results))
	}
	return results, err
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

	go func() {
		e.logger.Info("Starting proxy with strategy", "strategy", fp.Description, "address", p.Addr())
		err := p.Start()

		e.mu.Lock()
		defer e.mu.Unlock()
		// If the proxy was stopped gracefully, err will be non-nil.
		// We should only store the error if it was not a graceful stop.
		// A graceful stop is signaled by setting e.activeProxy to nil.
		if e.activeProxy != nil {
			e.proxyErrorChan <- err
			e.activeProxy = nil // Reset proxy on error
		}
	}()

	return nil
}

func (e *Engine) createDialerForStrategy(fp *config.Fingerprint) (proxy.CustomDialer, error) {
	// 1. Create the base dialer (TCP/QUIC with fragmentation)
	factory := &engine.DefaultDialerFactory{}
	baseDialer, err := factory.NewDialer(&fp.Transport, &fp.TLS)
	if err != nil {
		return nil, fmt.Errorf("failed to create base dialer: %w", err)
	}

	// 2. Create the full dialer function that includes the TLS layer
	fullDialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		rawConn, err := baseDialer(ctx, network, address)
		if err != nil {
			return nil, fmt.Errorf("base dialer failed: %w", err)
		}

		tlsConn, err := engine.NewTLSClient(rawConn, &fp.TLS)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("tls client creation failed: %w", err)
		}
		return tlsConn, nil
	}

	return fullDialer, nil
}

// GetBestStrategy tests all available strategies and returns the best one.
func (e *Engine) GetBestStrategy(ctx context.Context) (*config.Fingerprint, error) {
	e.logger.Info("Getting best strategy...")
	// Convert to slice of pointers for the ranker
	var fps []*config.Fingerprint
	for i := range e.fingerprints {
		fps = append(fps, &e.fingerprints[i])
	}
	results, err := e.ranker.TestAndRank(ctx, fps)
	if err != nil {
		return nil, fmt.Errorf("failed to test and rank strategies: %w", err)
	}

	for _, res := range results {
		if res.Success {
			e.logger.Info("Found best strategy", "id", res.Fingerprint.ID)
			return res.Fingerprint, nil
		}
	}

	e.logger.Warn("No successful strategy found")
	return nil, fmt.Errorf("no successful strategy found")
}

// GetStrategyByID returns a strategy fingerprint by its ID.
func (e *Engine) GetStrategyByID(id string) (*config.Fingerprint, error) {
	for i, fp := range e.fingerprints {
		if fp.ID == id {
			return &e.fingerprints[i], nil
		}
	}
	return nil, fmt.Errorf("strategy with ID '%s' not found", id)
}

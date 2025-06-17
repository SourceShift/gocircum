package core

import (
	"bufio"
	"context"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/engine"
	"gocircum/core/proxy"
	"gocircum/core/ranker"
	"gocircum/pkg/logging"
	"net"
	"net/http"
	"sync"
)

// Engine is the main controller for the circumvention library.
type Engine struct {
	ranker         *ranker.Ranker
	config         *config.FileConfig
	activeProxy    *proxy.Proxy
	mu             sync.Mutex
	proxyErrorChan chan error
	lastProxyError error
	logger         logging.Logger
	cancelProxy    context.CancelFunc
}

// NewEngine creates a new core engine with a given set of fingerprints.
func NewEngine(cfg *config.FileConfig, logger logging.Logger) (*Engine, error) {
	if len(cfg.Fingerprints) == 0 {
		return nil, fmt.Errorf("engine must be initialized with at least one fingerprint")
	}
	if logger == nil {
		logger = logging.GetLogger()
	}
	return &Engine{
		ranker:         ranker.NewRanker(logger),
		config:         cfg,
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

	if e.cancelProxy != nil {
		e.cancelProxy()
		e.cancelProxy = nil
	}

	err := e.activeProxy.Stop()
	if err != nil {
		return fmt.Errorf("failed to stop proxy: %w", err)
	}
	e.activeProxy = nil // Signal graceful shutdown
	return nil
}

// Status returns the current status of the proxy.
func (e *Engine) Status() (string, error) {
	e.mu.Lock()
	proxy := e.activeProxy
	lastErr := e.lastProxyError
	e.mu.Unlock()

	// Check for a new failure message first.
	select {
	case err := <-e.proxyErrorChan:
		e.mu.Lock()
		e.lastProxyError = err
		lastErr = err
		e.mu.Unlock()
		e.logger.Error("Proxy has failed", "error", err)
	default:
		// No immediate error, proceed.
	}

	// If we have a stored error, that's our state.
	if lastErr != nil {
		return "Proxy failed", lastErr
	}

	if proxy != nil {
		return fmt.Sprintf("Proxy running on %s", proxy.Addr()), nil
	}

	return "Proxy stopped", nil
}

// TestStrategies tests all available fingerprints and returns the ranked results.
func (e *Engine) TestStrategies(ctx context.Context) ([]ranker.StrategyResult, error) {
	e.logger.Info("Testing all strategies...")
	// Convert to slice of pointers for the ranker
	var fps []*config.Fingerprint
	for i := range e.config.Fingerprints {
		fps = append(fps, &e.config.Fingerprints[i])
	}
	results, err := e.ranker.TestAndRank(ctx, fps, e.config.CanaryDomains)
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

	// Create a new context for this proxy instance that we can cancel.
	_, cancel := context.WithCancel(context.Background())
	e.cancelProxy = cancel

	// Reset error state for the new proxy instance
	e.proxyErrorChan = make(chan error, 1)
	e.lastProxyError = nil

	go func() {
		e.logger.Info("Starting proxy with strategy", "strategy", fp.Description, "address", p.Addr())
		err := p.Start() // This is a blocking call

		// After Start() returns, the proxy has stopped, either gracefully or due to an error.
		e.mu.Lock()
		defer e.mu.Unlock()

		// If the proxy instance is the one we started, it means it wasn't a planned Stop().
		if e.activeProxy == p {
			if err != nil {
				e.logger.Error("Proxy stopped with an error", "error", err)
				// Use a non-blocking send in case the channel is full or no one is listening.
				select {
				case e.proxyErrorChan <- err:
				default:
				}
			}
			e.activeProxy = nil // It has stopped, so clear it.
		}
		// If e.activeProxy is nil or a different instance, it means Stop() was called.
		// In that case, we don't need to do anything.
	}()

	return nil
}

// establishHTTPConnectTunnel sends an HTTP CONNECT request to establish a tunnel.
func establishHTTPConnectTunnel(conn net.Conn, covertTarget, finalDestination string) error {
	req, err := http.NewRequest("CONNECT", "http://"+finalDestination, nil)
	if err != nil {
		return fmt.Errorf("failed to create CONNECT request: %w", err)
	}
	req.Host = covertTarget
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")

	if err := req.Write(conn); err != nil {
		return fmt.Errorf("failed to write CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("CONNECT request failed with status: %s", resp.Status)
	}

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
		if fp.DomainFronting != nil && fp.DomainFronting.Enabled {
			e.logger.Info("Using domain fronting", "strategy", fp.ID, "front_domain", fp.DomainFronting.FrontDomain)

			// For domain fronting, we dial the front domain. 'address' is the final destination.
			dialAddr := fp.DomainFronting.FrontDomain
			sni := fp.DomainFronting.FrontDomain

			// 1. Dial the front domain
			rawConn, err := baseDialer(ctx, network, dialAddr)
			if err != nil {
				return nil, fmt.Errorf("base dialer failed for front domain %s: %w", dialAddr, err)
			}

			// 2. Establish TLS with SNI set to front domain
			tlsConn, err := engine.NewTLSClient(rawConn, &fp.TLS, sni, nil)
			if err != nil {
				rawConn.Close()
				return nil, fmt.Errorf("tls client creation failed for front domain: %w", err)
			}

			// 3. Establish HTTP CONNECT tunnel to the actual destination ('address')
			if err := establishHTTPConnectTunnel(tlsConn, fp.DomainFronting.CovertTarget, address); err != nil {
				tlsConn.Close()
				return nil, fmt.Errorf("http connect tunnel failed for %s: %w", address, err)
			}

			e.logger.Info("Domain fronting tunnel established", "covert_target", address)
			return tlsConn, nil
		}

		// Original path for non-domain-fronting
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			// If SplitHostPort fails, it might be because the port is missing.
			// In that case, the address is likely the host.
			// We log a warning but proceed.
			e.logger.Warn("Could not split host/port, using address as host for SNI", "address", address, "error", err)
			host = address
		}
		rawConn, err := baseDialer(ctx, network, address)
		if err != nil {
			return nil, fmt.Errorf("base dialer failed for %s: %w", address, err)
		}

		tlsConn, err := engine.NewTLSClient(rawConn, &fp.TLS, host, nil) // Pass parsed host as SNI
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
	for i := range e.config.Fingerprints {
		fps = append(fps, &e.config.Fingerprints[i])
	}
	results, err := e.ranker.TestAndRank(ctx, fps, e.config.CanaryDomains)
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
	for i, fp := range e.config.Fingerprints {
		if fp.ID == id {
			return &e.config.Fingerprints[i], nil
		}
	}
	return nil, fmt.Errorf("strategy with ID '%s' not found", id)
}

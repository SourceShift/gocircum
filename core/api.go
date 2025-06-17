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
		ranker:         ranker.NewRanker(logger, cfg.DoHProviders),
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

// StartProxyWithStrategy starts the SOCKS5 proxy with a specific strategy.
// It returns the actual listening address (which may be different from the provided
// address if a random port was requested) and an error if one occurred.
func (e *Engine) StartProxyWithStrategy(ctx context.Context, addr string, strategy *config.Fingerprint) (string, error) {
	e.logger.Debug("starting proxy with strategy", "strategy_id", strategy.ID, "listen_addr", addr)
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeProxy != nil {
		return "", fmt.Errorf("a proxy is already running on %s", e.activeProxy.Addr())
	}

	dialer, err := e.createDialerForStrategy(strategy)
	if err != nil {
		return "", fmt.Errorf("could not create dialer for strategy %s: %w", strategy.ID, err)
	}

	p, err := proxy.New(addr, dialer, e.config.DoHProviders)
	if err != nil {
		return "", fmt.Errorf("failed to create socks5 server: %w", err)
	}
	e.activeProxy = p

	go func() {
		e.logger.Info("Starting proxy with strategy", "strategy", strategy.Description, "address", p.Addr())
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
	}()

	return p.Addr(), nil
}

// establishHTTPConnectTunnel sends an HTTP CONNECT request to establish a tunnel.
func establishHTTPConnectTunnel(conn net.Conn, covertTarget, finalDestination, userAgent string) error {
	req, err := http.NewRequest("CONNECT", "http://"+finalDestination, nil)
	if err != nil {
		return fmt.Errorf("failed to create CONNECT request: %w", err)
	}
	req.Host = covertTarget
	if userAgent == "" {
		userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
	}
	req.Header.Set("User-Agent", userAgent)

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

// createDomainFrontingDialer handles the secure connection logic for domain fronting.
func (e *Engine) createDomainFrontingDialer(fp *config.Fingerprint, baseDialer engine.Dialer) (proxy.CustomDialer, error) {
	return func(ctx context.Context, network, finalDestination string) (net.Conn, error) {
		frontHost, frontPort, err := net.SplitHostPort(fp.DomainFronting.FrontDomain)
		if err != nil {
			frontHost = fp.DomainFronting.FrontDomain
			frontPort = "443" // Default HTTPS port
		}

		// Securely resolve fronting domain to an IP to prevent DNS leaks.
		_, frontIP, err := e.ranker.DoHResolver.Resolve(ctx, frontHost)
		if err != nil {
			return nil, fmt.Errorf("securely resolving front domain %s failed: %w", frontHost, err)
		}
		dialAddr := net.JoinHostPort(frontIP.String(), frontPort)

		// 1. Dial the front domain's IP address.
		rawConn, err := baseDialer(ctx, network, dialAddr)
		if err != nil {
			return nil, fmt.Errorf("base dialer failed for front domain %s (%s): %w", frontHost, dialAddr, err)
		}

		// 2. Establish TLS with SNI set to the benign front domain.
		tlsConn, err := engine.NewTLSClient(rawConn, &fp.TLS, frontHost, nil)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("tls client creation failed for front domain: %w", err)
		}

		// 3. Establish HTTP CONNECT tunnel to the actual destination.
		if err := establishHTTPConnectTunnel(tlsConn, fp.DomainFronting.CovertTarget, finalDestination, fp.TLS.UserAgent); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("http connect tunnel failed for %s: %w", finalDestination, err)
		}

		e.logger.Info("Domain fronting tunnel established", "final_destination", finalDestination)
		return tlsConn, nil
	}, nil
}

// THIS FUNCTION HAS BEEN REMOVED.
// There should be no code path that allows for direct, un-fronted connections
// that leak the destination SNI. All connections must use a secure dialer
// like the domain fronting dialer.

func (e *Engine) createDialerForStrategy(fp *config.Fingerprint) (proxy.CustomDialer, error) {
	factory := &engine.DefaultDialerFactory{}
	baseDialer, err := factory.NewDialer(&fp.Transport, &fp.TLS)
	if err != nil {
		return nil, fmt.Errorf("failed to create base dialer: %w", err)
	}

	// Enforce secure-by-default: only domain fronting is allowed.
	if fp.DomainFronting != nil && fp.DomainFronting.Enabled {
		e.logger.Info("Creating dialer with Domain Fronting strategy.", "strategy_id", fp.ID)
		return e.createDomainFrontingDialer(fp, baseDialer)
	}

	// Reject any strategy that does not explicitly enable domain fronting.
	// This prevents accidental use of insecure direct connections.
	return nil, fmt.Errorf("security policy violation: strategy '%s' must have domain_fronting enabled. Direct connections with SNI leakage are not permitted", fp.ID)
}

// GetBestStrategy finds the best available strategy by testing and ranking them.
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

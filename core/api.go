package core

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/x509"
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
	dialerFactory  *engine.DefaultDialerFactory
}

// NewEngine creates a new core engine with a given set of fingerprints.
func NewEngine(cfg *config.FileConfig, logger logging.Logger) (*Engine, error) {
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}
	if logger == nil {
		logger = logging.GetLogger()
	}

	var rankerInstance *ranker.Ranker
	var err error
	if len(cfg.DoHProviders) > 0 {
		rankerInstance, err = ranker.NewRanker(logger, cfg.DoHProviders)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize engine: %w", err)
		}
	}

	return &Engine{
		ranker:         rankerInstance,
		config:         cfg,
		proxyErrorChan: make(chan error, 1),
		logger:         logger.With("component", "engine"),
		dialerFactory:  &engine.DefaultDialerFactory{},
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
	if e.ranker == nil {
		return nil, fmt.Errorf("cannot test strategies: engine was initialized without DoH providers")
	}
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

	dohResolver, err := proxy.NewDoHResolver(e.config.DoHProviders)
	if err != nil {
		return "", fmt.Errorf("failed to create DoH resolver for proxy: %w", err)
	}

	p, err := proxy.New(addr, dialer, dohResolver)
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

// establishHTTPConnectTunnel sends a padded and fragmented HTTP CONNECT request to establish a tunnel.
func establishHTTPConnectTunnel(conn net.Conn, target, host string, userAgent string) error {
	req, err := http.NewRequest("CONNECT", "http://"+target, nil)
	if err != nil {
		return fmt.Errorf("failed to create CONNECT request: %w", err)
	}
	req.Host = host
	if userAgent == "" {
		ua, err := getRandomUserAgent()
		if err != nil {
			return fmt.Errorf("failed to get random user agent: %w", err)
		}
		req.Header.Set("User-Agent", ua)
	} else {
		req.Header.Set("User-Agent", userAgent)
	}

	// Add random padding headers to obfuscate the request size.
	paddingHeaders, _ := engine.CryptoRandInt(2, 5)
	for i := 0; i < int(paddingHeaders); i++ {
		keyBytes := make([]byte, 8)
		valBytes := make([]byte, 16)
		_, _ = rand.Read(keyBytes)
		_, _ = rand.Read(valBytes)
		req.Header.Add(fmt.Sprintf("X-Padding-%x", keyBytes), fmt.Sprintf("%x", valBytes))
	}

	err = req.Write(conn)
	if err != nil {
		return fmt.Errorf("failed to write CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy CONNECT request failed with status: %s", resp.Status)
	}

	return nil
}

// NewTLSClient is DEPRECATED. Use engine.NewUTLSClient instead.
func (e *Engine) NewTLSClient(rawConn net.Conn, tlsCfg *config.TLS, sni string, customRootCAs *x509.CertPool) (net.Conn, error) {
	return engine.NewUTLSClient(rawConn, tlsCfg, sni, customRootCAs)
}

// createDomainFrontingDialer handles the secure connection logic for domain fronting.
func (e *Engine) createDomainFrontingDialer(fp *config.Fingerprint, dialer engine.Dialer) engine.Dialer {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		// The `address` parameter from the SOCKS5 client is ignored;
		// we always connect to the fronting domain.
		rawConn, err := dialer(ctx, network, fp.DomainFronting.FrontDomain)
		if err != nil {
			return nil, fmt.Errorf("failed to dial front domain %s: %w", fp.DomainFronting.FrontDomain, err)
		}

		// Now, wrap the raw connection with TLS and send the CONNECT request.
		tlsConn, err := engine.NewUTLSClient(rawConn, &fp.TLS, fp.DomainFronting.FrontDomain, nil)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("failed to establish TLS with front domain: %w", err)
		}

		// The host header is what the proxy server sees, while the SNI is what the
		// TLS terminator (e.g., a CDN) sees. For domain fronting, these must be different.
		hostHeader := fp.DomainFronting.CovertTarget
		if hostHeader == "" {
			hostHeader = address
		}
		ua, _ := getRandomUserAgent()
		err = establishHTTPConnectTunnel(tlsConn, address, hostHeader, ua)
		if err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("failed to establish CONNECT tunnel: %w", err)
		}
		return tlsConn, nil
	}
}

// createDialerForStrategy creates a base dialer from a fingerprint.
func (e *Engine) createDialerForStrategy(fp *config.Fingerprint) (engine.Dialer, error) {
	// Enforce security policy at runtime. All strategies MUST use domain fronting.
	if fp.DomainFronting == nil || !fp.DomainFronting.Enabled {
		return nil, fmt.Errorf("security policy violation: strategy '%s' must have domain_fronting enabled", fp.ID)
	}

	// 1. Create the base dialer (TCP or QUIC) without domain fronting logic.
	baseDialer, err := e.dialerFactory.NewDialer(&fp.Transport, &fp.TLS)
	if err != nil {
		return nil, fmt.Errorf("failed to create base dialer: %w", err)
	}

	// 2. The only allowed path is to wrap the base dialer with the domain fronting dialer.
	return e.createDomainFrontingDialer(fp, baseDialer), nil
}

// GetBestStrategy ranks all strategies and returns the one with the best performance.
func (e *Engine) GetBestStrategy(ctx context.Context) (*config.Fingerprint, error) {
	if e.ranker == nil {
		return nil, fmt.Errorf("cannot get best strategy: engine was initialized without DoH providers")
	}
	e.logger.Info("Getting best strategy...")
	results, err := e.TestStrategies(ctx)
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

// NewProxyForStrategy creates a new proxy instance for a given strategy.
// This is useful for creating multiple proxy instances. It is the caller's
// responsibility to manage the lifecycle of the returned proxy.
func (e *Engine) NewProxyForStrategy(ctx context.Context, listenAddr string, fp *config.Fingerprint, resolver *proxy.DoHResolver) (*proxy.Proxy, error) {
	// 1. Create a custom dialer for the strategy
	dialer, err := e.createDialerForStrategy(fp)
	if err != nil {
		return nil, fmt.Errorf("failed to create dialer for strategy %s: %w", fp.ID, err)
	}

	// 2. Wrap the dialer in a CONNECT tunnel if domain fronting is enabled
	if fp.DomainFronting != nil && fp.DomainFronting.Enabled {
		dialer = e.createDomainFrontingDialer(fp, dialer)
	}

	// 3. Create the SOCKS5 proxy with the custom dialer and DoH resolver
	proxyServer, err := proxy.New(listenAddr, dialer, resolver)
	if err != nil {
		return nil, fmt.Errorf("failed to create proxy for strategy %s: %w", fp.ID, err)
	}
	return proxyServer, nil
}

func getRandomUserAgent() (string, error) {
	uaIndex, err := engine.CryptoRandInt(0, len(engine.PopularUserAgents)-1)
	if err != nil {
		return "", fmt.Errorf("failed to get random user agent: %w", err)
	}
	return engine.PopularUserAgents[uaIndex], nil
}

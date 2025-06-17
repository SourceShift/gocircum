package core

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"gocircum/core/config"
	"gocircum/core/engine"
	"gocircum/core/proxy"
	"gocircum/core/ranker"
	"gocircum/pkg/logging"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var popularUserAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
}

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
func establishHTTPConnectTunnel(conn net.Conn, covertTarget, finalDestination, userAgent string) error {
	req, err := http.NewRequest("CONNECT", "http://"+finalDestination, nil)
	if err != nil {
		return fmt.Errorf("failed to create CONNECT request: %w", err)
	}
	req.Host = covertTarget
	if userAgent == "" {
		// Randomly select a popular User-Agent to avoid a static fingerprint.
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(popularUserAgents))))
		if err != nil {
			// Fallback to the first one on the rare chance of a crypto/rand error.
			userAgent = popularUserAgents[0]
		} else {
			userAgent = popularUserAgents[n.Int64()]
		}
	}
	req.Header.Set("User-Agent", userAgent)

	// Add random padding headers to obfuscate the request size.
	paddingHeaders, _ := engine.CryptoRandInt(2, 5)
	for i := 0; i < int(paddingHeaders); i++ {
		keyBytes := make([]byte, 8)
		valBytes := make([]byte, 16)
		_, _ = rand.Read(keyBytes)
		_, _ = rand.Read(valBytes)
		req.Header.Set(fmt.Sprintf("X-Padding-%x", keyBytes), fmt.Sprintf("%x", valBytes))
	}

	// Convert the request to bytes to be sent manually.
	var buf strings.Builder
	if err := req.Write(&buf); err != nil {
		return fmt.Errorf("failed to buffer CONNECT request: %w", err)
	}
	requestBytes := []byte(buf.String())

	// Fragment the request write to break the packet fingerprint.
	offset := 0
	for offset < len(requestBytes) {
		maxChunk, _ := engine.CryptoRandInt(10, 50)
		chunkSize := int(maxChunk)
		if offset+chunkSize > len(requestBytes) {
			chunkSize = len(requestBytes) - offset
		}

		if _, err := conn.Write(requestBytes[offset : offset+chunkSize]); err != nil {
			return fmt.Errorf("failed to write fragmented CONNECT request: %w", err)
		}
		offset += chunkSize

		if offset < len(requestBytes) {
			delay, _ := engine.CryptoRandInt(5, 20)
			time.Sleep(time.Duration(delay) * time.Millisecond)
		}
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

		// 3. Establish a CONNECT tunnel to the final destination through the fronted connection.
		if err := establishHTTPConnectTunnel(tlsConn, fp.DomainFronting.CovertTarget, finalDestination, fp.TLS.UserAgent); err != nil {
			tlsConn.Close()
			return nil, fmt.Errorf("http connect tunnel failed: %w", err)
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
	// 1. Create the base dialer (TCP or QUIC) without domain fronting logic.
	dialerFactory := &engine.DefaultDialerFactory{}
	baseDialer, err := dialerFactory.NewDialer(&fp.Transport, &fp.TLS)
	if err != nil {
		return nil, fmt.Errorf("failed to create base dialer: %w", err)
	}

	// 2. If domain fronting is enabled, wrap the base dialer.
	if fp.DomainFronting != nil && fp.DomainFronting.Enabled {
		return e.createDomainFrontingDialer(fp, baseDialer)
	}

	// 3. If no domain fronting, the dialer connects directly.
	// This path is now strongly discouraged due to fingerprinting risks.
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		e.logger.Warn("SECURITY WARNING: Using a strategy without domain fronting. This is highly fingerprintable and not recommended.", "strategy_id", fp.ID)
		return baseDialer(ctx, network, addr)
	}, nil
}

// GetBestStrategy finds the best available strategy by testing and ranking them.
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

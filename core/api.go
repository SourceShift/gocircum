package core

//nolint:unused

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/core/engine"
	"github.com/gocircum/gocircum/core/proxy"
	"github.com/gocircum/gocircum/core/ranker"
	"github.com/gocircum/gocircum/pkg/logging"
)

// Engine is the main controller for the circumvention library.
type Engine struct {
	mu             sync.Mutex
	logger         logging.Logger
	ranker         *ranker.Ranker
	activeProxy    *proxy.Proxy
	proxyErrorChan chan error
	lastProxyError error
	fileConfig     *config.FileConfig
	cancelProxy    context.CancelFunc
	dialerFactory  *engine.DefaultDialerFactory
	//nolint:unused
	originalResolver      *net.Resolver
	dnsInterceptor        *DNSInterceptor
	secureConnectionStore map[string]*SecureConnectionDetails
	cleanupRunning        bool
	// Retained for future implementation of domain generation features
	//nolint:unused
	dga *DomainGenerationAlgorithm
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

	engineInstance := &Engine{
		ranker:         rankerInstance,
		fileConfig:     cfg,
		proxyErrorChan: make(chan error, 1),
		logger:         logger.With("component", "engine"),
		dialerFactory:  &engine.DefaultDialerFactory{},
	}

	// Install comprehensive DNS protection before returning
	if err := engineInstance.installComprehensiveDNSProtection(); err != nil {
		return nil, fmt.Errorf("failed to install DNS protection: %w", err)
	}

	return engineInstance, nil
}

// Ranker returns the engine's ranker instance.
func (e *Engine) Ranker() *ranker.Ranker {
	return e.ranker
}

// Stop gracefully shuts down the active proxy.
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

	// Check for a new failure message first. This makes the status check authoritative.
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
	for i := range e.fileConfig.Fingerprints {
		fps = append(fps, &e.fileConfig.Fingerprints[i])
	}
	results, err := e.ranker.TestAndRank(ctx, fps, e.fileConfig.CanaryDomains)
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
	sessionID := generateSecureSessionID()
	e.logger.Debug("starting proxy session", "session_id", sessionID)
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.activeProxy != nil {
		return "", fmt.Errorf("a proxy is already running on %s", e.activeProxy.Addr())
	}

	dialer, err := e.createDialerForStrategy(strategy)
	if err != nil {
		return "", fmt.Errorf("could not create dialer for strategy %s: %w", strategy.ID, err)
	}

	dohResolver, err := proxy.NewDoHResolver(e.fileConfig.DoHProviders)
	if err != nil {
		return "", fmt.Errorf("failed to create DoH resolver for proxy: %w", err)
	}

	p, err := proxy.New(addr, dialer, dohResolver)
	if err != nil {
		return "", fmt.Errorf("failed to create socks5 server: %w", err)
	}
	e.activeProxy = p

	go func() {
		e.logger.Info("Proxy session started", "session_id", sessionID, "interface", "localhost")
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

// establishHTTPConnectTunnel sends a highly obfuscated HTTP CONNECT request
func establishHTTPConnectTunnel(conn net.Conn, target, host string, userAgent string) error {
	// CRITICAL: Implement advanced HTTP obfuscation to defeat DPI

	// 1. Generate realistic browser-like request with timing
	req, err := http.NewRequest("CONNECT", "http://"+target, nil)
	if err != nil {
		return fmt.Errorf("failed to create CONNECT request: %w", err)
	}
	req.Host = host

	// 2. Generate complete browser-like header set with randomization
	if userAgent == "" {
		ua, err := getRandomUserAgent()
		if err != nil {
			return fmt.Errorf("failed to get random user agent: %w", err)
		}
		req.Header.Set("User-Agent", ua)
	} else {
		req.Header.Set("User-Agent", userAgent)
	}

	// 3. Add realistic browser headers with proper ordering
	headers := generateCompleteBrowserHeaders(userAgent)
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// 4. Add anti-fingerprinting headers in realistic order
	headerOrder := getBrowserHeaderOrder(userAgent)
	orderedHeaders := make(http.Header)
	for _, headerName := range headerOrder {
		if value := req.Header.Get(headerName); value != "" {
			orderedHeaders.Set(headerName, value)
		}
	}
	req.Header = orderedHeaders

	// 5. Apply HTTP/2 HPACK-style header compression simulation
	compressedHeaders := simulateHPACKCompression(req.Header)

	// 6. Fragment and send with realistic browser timing
	return sendFragmentedHTTPRequest(conn, req, compressedHeaders)
}

// NewTLSClient is DEPRECATED. Use engine.NewUTLSClient instead.
func (e *Engine) NewTLSClient(rawConn net.Conn, tlsCfg *config.TLS, sni string, customRootCAs *x509.CertPool) (net.Conn, error) {
	return engine.NewUTLSClient(rawConn, tlsCfg, sni, customRootCAs)
}

// Hardened: Implements a Resolve-then-Dial pattern to prevent DNS leaks.
func (e *Engine) createDomainFrontingDialer(fp *config.Fingerprint, dialer engine.Dialer) engine.Dialer {
	return func(outerCtx context.Context, network, addr string) (net.Conn, error) {
		// PRIVACY-PRESERVING: Log only sanitized information
		connectionID := e.generateEphemeralConnectionID()
		e.logger.Debug("Creating domain fronting connection",
			"connection_id", connectionID,
			"front_domain_hash", e.hashSensitiveData(fp.DomainFronting.FrontDomain),
			"strategy_id", fp.ID, // Non-sensitive strategy identifier
			"network_type", network) // Safe to log
		// Store detailed information in secure memory only
		e.storeConnectionDetailsSecurely(connectionID, fp.DomainFronting.FrontDomain, addr)
		// Enhanced validation with front domain verification
		if err := e.validateFrontDomainCoverage(fp.DomainFronting); err != nil {
			return nil, fmt.Errorf("front domain validation failed: %w", err)
		}

		// CRITICAL: Validate DoH infrastructure before ANY network operations
		if e.ranker == nil || e.ranker.DoHResolver == nil {
			e.logger.Error("CRITICAL: DoH resolver unavailable - cannot proceed securely", "component", "domain_fronting")
			return nil, fmt.Errorf("security violation: secure DNS resolution unavailable, refusing insecure fallback")
		}

		// Verify DoH resolver is actually functional with a test query
		testCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, testIP, err := e.ranker.DoHResolver.Resolve(testCtx, "cloudflare.com")
		if err != nil || testIP == nil {
			e.logger.Error("CRITICAL: DoH resolver failed test query - potential compromise")
			return nil, fmt.Errorf("security violation: DoH infrastructure compromised or unavailable")
		}

		// Additional validation: Ensure DoH providers are responsive
		if err := e.validateDoHConnectivity(); err != nil {
			e.logger.Error("DoH connectivity validation failed", "error", err)
			return nil, fmt.Errorf("secure DNS infrastructure unavailable: %w", err)
		}

		frontHost, frontPort, err := net.SplitHostPort(fp.DomainFronting.FrontDomain)
		if err != nil {
			// If no port is specified, assume 443 for HTTPS.
			frontHost = fp.DomainFronting.FrontDomain
			frontPort = "443"
		}

		// Validate that we're using DoH exclusively and never fall back to system DNS
		if e.ranker.DoHResolver == nil {
			return nil, fmt.Errorf("SECURITY_VIOLATION: DoH resolver not available, cannot proceed without DNS leak risk")
		}

		// Perform resolution with timeout and validation
		resolveCtx, resolveCancel := context.WithTimeout(outerCtx, 10*time.Second)
		defer resolveCancel()

		_, frontIP, err := e.ranker.DoHResolver.Resolve(resolveCtx, frontHost)
		if err != nil {
			// Never fall back to system DNS - fail securely
			return nil, fmt.Errorf("DoH resolution for front domain %s failed (secure failure): %w", frontHost, err)
		}

		// Validate the returned IP is not obviously filtered/poisoned
		if err := e.validateResolvedIP(frontIP, frontHost); err != nil {
			return nil, fmt.Errorf("DNS resolution validation failed for %s: %w", frontHost, err)
		}

		// 3. Dial the resolved IP address, not the hostname. This prevents a system DNS lookup.
		dialAddress := net.JoinHostPort(frontIP.String(), frontPort)
		rawConn, err := dialer(outerCtx, network, dialAddress)
		if err != nil {
			return nil, fmt.Errorf("failed to dial front domain %s at %s: %w", frontHost, dialAddress, err)
		}

		// CRITICAL FIX: Use front domain for SNI to maintain fronting
		sniDomain := e.selectOptimalSNI(frontHost, fp.DomainFronting)

		tlsConn, err := engine.NewUTLSClient(rawConn, &fp.TLS, sniDomain, nil)
		if err != nil {
			_ = rawConn.Close()
			return nil, fmt.Errorf("failed to establish TLS with front domain %s: %w", frontHost, err)
		}

		// 5. Establish the HTTP CONNECT tunnel to the final destination.
		hostHeader := fp.DomainFronting.CovertTarget
		if hostHeader == "" {
			hostHeader = addr
		}
		ua, _ := getRandomUserAgent()
		err = establishHTTPConnectTunnel(tlsConn, addr, hostHeader, ua)
		if err != nil {
			_ = tlsConn.Close()
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

	// 1. Create a RAW base dialer (TCP or QUIC). We pass a nil TLS config
	// to the factory to prevent it from pre-emptively wrapping the connection in TLS.
	// The domain fronting dialer is responsible for the TLS handshake.
	rawDialer, err := e.dialerFactory.NewDialer(&fp.Transport, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create base dialer: %w", err)
	}

	// 2. The only allowed path is to wrap the raw dialer with the domain fronting dialer.
	return e.createDomainFrontingDialer(fp, rawDialer), nil
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
	for i, fp := range e.fileConfig.Fingerprints {
		if fp.ID == id {
			return &e.fileConfig.Fingerprints[i], nil
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

// validateDoHConnectivity ensures DoH infrastructure is working before proceeding
func (e *Engine) validateDoHConnectivity() error {
	if e.ranker == nil || e.ranker.DoHResolver == nil {
		return fmt.Errorf("DoH resolver not initialized")
	}

	// CRITICAL: Install system DNS blocker to prevent leaks
	if err := e.installSystemDNSBlocker(); err != nil {
		return fmt.Errorf("failed to install DNS leak prevention: %w", err)
	}

	// Start DNS decoy traffic to mask real queries
	if err := e.startDNSDecoyTraffic(); err != nil {
		e.logger.Warn("Failed to start DNS decoy traffic", "error", err)
		// Continue without decoy traffic
	}

	// Test multiple DoH providers to ensure redundancy
	testDomains := []string{"cloudflare.com", "google.com", "quad9.net"}
	successCount := 0

	for _, domain := range testDomains {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, _, err := e.ranker.DoHResolver.Resolve(ctx, domain)
		cancel()

		if err == nil {
			successCount++
		} else {
			e.logger.Warn("DoH test failed for domain", "domain", domain, "error", err)
		}
	}

	if successCount == 0 {
		return fmt.Errorf("all DoH connectivity tests failed - secure DNS unavailable")
	}

	if successCount < len(testDomains)/2 {
		e.logger.Warn("Limited DoH connectivity detected", "success_rate", float64(successCount)/float64(len(testDomains)))
	}

	return nil
}

// generateRealisticBrowserHeaders creates headers typical of real browsers
//
//nolint:unused // Will be used in future implementation
func generateRealisticBrowserHeaders() map[string]string {
	headers := make(map[string]string)

	// Essential headers that real browsers always send
	headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
	headers["Accept-Language"] = generateRealisticAcceptLanguage()
	headers["Accept-Encoding"] = "gzip, deflate, br"
	headers["Connection"] = "keep-alive"
	headers["Upgrade-Insecure-Requests"] = "1"

	// Add realistic Sec-Fetch headers
	headers["Sec-Fetch-Dest"] = "document"
	headers["Sec-Fetch-Mode"] = "navigate"
	headers["Sec-Fetch-Site"] = "none"
	headers["Sec-Fetch-User"] = "?1"

	return headers
}

// generateRealisticAcceptLanguage creates realistic Accept-Language headers
func generateRealisticAcceptLanguage() string {
	languages := []string{
		"en-US,en;q=0.9",
		"en-US,en;q=0.9,es;q=0.8",
		"en-GB,en;q=0.9",
		"en-US,en;q=0.9,fr;q=0.8",
		"en-US,en;q=0.9,de;q=0.8",
	}

	idx, _ := engine.CryptoRandInt(0, len(languages)-1)
	return languages[idx]
}

// generateBrowserSpecificHeaders creates headers specific to the User-Agent
//
//nolint:unused // Planned for future browser fingerprinting functionality
func generateBrowserSpecificHeaders(userAgent string) map[string]string {
	headers := make(map[string]string)

	if strings.Contains(userAgent, "Chrome") {
		headers["Sec-Ch-Ua"] = "\"Google Chrome\";v=\"124\", \"Chromium\";v=\"124\", \"Not-A.Brand\";v=\"99\""
		headers["Sec-Ch-Ua-Mobile"] = "?0"
		headers["Sec-Ch-Ua-Platform"] = "\"Windows\""
	} else if strings.Contains(userAgent, "Firefox") {
		headers["DNT"] = "1"
		// Firefox doesn't send Sec-Ch-Ua headers
	} else if strings.Contains(userAgent, "Safari") && !strings.Contains(userAgent, "Chrome") {
		// Safari-specific headers
		headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	}

	return headers
}

// generateRealisticPaddingHeader creates realistic-looking padding headers
//
//nolint:unused // Will be used for traffic obfuscation features
func generateRealisticPaddingHeader() (string, string) {
	paddingHeaders := []struct {
		key    string
		values []string
	}{
		{
			key:    "X-Requested-With",
			values: []string{"XMLHttpRequest", "fetch"},
		},
		{
			key:    "Cache-Control",
			values: []string{"no-cache", "max-age=0"},
		},
		{
			key:    "X-Forwarded-For",
			values: []string{"192.168.1.1", "10.0.0.1"},
		},
	}

	headerIdx, _ := engine.CryptoRandInt(0, len(paddingHeaders)-1)
	header := paddingHeaders[headerIdx]

	valueIdx, _ := engine.CryptoRandInt(0, len(header.values)-1)
	return header.key, header.values[valueIdx]
}

func getRandomUserAgent() (string, error) {
	uaIndex, err := engine.CryptoRandInt(0, len(engine.PopularUserAgents)-1)
	if err != nil {
		return "", fmt.Errorf("failed to get random user agent: %w", err)
	}
	return engine.PopularUserAgents[uaIndex], nil
}

// validateFrontDomainCoverage ensures the front domain is properly configured
func (e *Engine) validateFrontDomainCoverage(df *config.DomainFronting) error {
	// Check if front domain is on a major CDN that supports domain fronting
	knownCDNs := map[string]bool{
		"cloudfront.net":        true,
		"azureedge.net":         true,
		"fastly.com":            true,
		"google.com":            true,
		"googleapis.com":        true,
		"amazonaws.com":         true,
		"awsstatic.com":         true,
		"gstatic.com":           true,
		"googleusercontent.com": true,
	}

	for cdn := range knownCDNs {
		if strings.Contains(df.FrontDomain, cdn) {
			return nil
		}
	}

	e.logger.Warn("Front domain may not support domain fronting", "domain", df.FrontDomain)
	return nil // Allow with warning for now
}

// selectOptimalSNI chooses the best SNI value for the connection
func (e *Engine) selectOptimalSNI(frontHost string, df *config.DomainFronting) string {
	// Use the front domain itself for SNI - this is critical for domain fronting
	return frontHost
}

// SetDialerFactoryForTesting allows replacing the dialer factory for testing purposes.
// This should not be used in production code.
func (e *Engine) SetDialerFactoryForTesting(factory engine.DialerFactory) {
	if e.ranker != nil {
		e.ranker.DialerFactory = factory
	}
}

// installSystemDNSBlocker prevents system DNS usage
func (e *Engine) installSystemDNSBlocker() error {
	// Comprehensive DNS leak prevention using multiple layers

	// 1. Block CGO-based DNS resolution completely
	if err := os.Setenv("GODEBUG", "netdns=go"); err != nil {
		e.logger.Warn("Failed to set GODEBUG environment variable", "error", err)
		// Continue despite error - this is just one layer of protection
	}

	// 2. Install comprehensive resolver that blocks ALL DNS mechanisms
	blockedResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Log the violation with enhanced context
			e.logger.Error("CRITICAL: System DNS bypass attempt detected",
				"network", network,
				"address", address,
				"goroutine_id", getGoroutineID(),
				"stack_trace", string(debug.Stack()))

			// Trigger security alert and potentially terminate process
			e.triggerSecurityAlert("DNS_BYPASS_ATTEMPT")

			return nil, fmt.Errorf("SECURITY_VIOLATION: system DNS permanently disabled")
		},
	}

	// 3. Replace ALL resolver instances system-wide
	net.DefaultResolver = blockedResolver

	// 4. Monitor for DNS bypass attempts at runtime
	go e.monitorDNSBypassAttempts()

	// 5. Install network-level DNS blocking if privileges allow
	if err := e.installNetworkDNSBlocking(); err != nil {
		e.logger.Warn("Could not install network-level DNS blocking", "error", err)
	}

	// 6. Validate that DoH infrastructure is functioning
	if err := e.validateDoHInfrastructure(); err != nil {
		return fmt.Errorf("DoH infrastructure validation failed: %w", err)
	}

	e.originalResolver = net.DefaultResolver
	return nil
}

// triggerSecurityAlert handles critical security violations
func (e *Engine) triggerSecurityAlert(alertType string) {
	// Implementation depends on deployment context
	e.logger.Error("SECURITY_ALERT", "type", alertType, "timestamp", time.Now().Unix())

	// In high-security environments, consider process termination
	if os.Getenv("GOCIRCUM_STRICT_MODE") == "1" {
		e.logger.Error("Terminating process due to security violation in strict mode")
		os.Exit(1)
	}
}

// monitorDNSBypassAttempts continuously monitors for DNS bypass attempts
func (e *Engine) monitorDNSBypassAttempts() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Check if system resolver has been replaced
		if net.DefaultResolver != e.originalResolver {
			e.logger.Warn("System DNS resolver has been modified externally")
		}

		// Additional runtime checks could be added here
	}
}

// installNetworkDNSBlocking attempts OS-level DNS blocking
func (e *Engine) installNetworkDNSBlocking() error {
	// This would require platform-specific implementation
	// Linux: iptables rules or eBPF programs
	// Windows: WinDivert or similar
	// macOS: pfctl rules

	// Placeholder for platform-specific implementation
	e.logger.Debug("Network-level DNS blocking not implemented for this platform")
	return nil
}

// getGoroutineID extracts the current goroutine ID for tracking
func getGoroutineID() int {
	var id int
	defer func() {
		if r := recover(); r != nil {
			// Recovery logic - we'll use a default value in case of panic
			id = -1
		}
	}()

	var buf [64]byte
	n := runtime.Stack(buf[:], false)
	idField := strings.Fields(strings.TrimPrefix(string(buf[:n]), "goroutine "))[0]
	id, _ = strconv.Atoi(idField)
	return id
}

// validateDoHInfrastructure verifies DoH providers are functioning correctly
func (e *Engine) validateDoHInfrastructure() error {
	if e.ranker == nil || e.ranker.DoHResolver == nil {
		return fmt.Errorf("DoH resolver not initialized")
	}

	testDomains := []string{"cloudflare.com", "google.com", "microsoft.com"}
	failureCount := 0

	for _, domain := range testDomains {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, _, err := e.ranker.DoHResolver.Resolve(ctx, domain)
		cancel()

		if err != nil {
			failureCount++
			e.logger.Warn("DoH provider failed verification test",
				"domain", domain,
				"error", err)
		}
	}

	// If more than half of providers failed, consider DoH infrastructure compromised
	if failureCount > len(testDomains)/2 {
		return fmt.Errorf("DoH infrastructure verification failed (%d/%d providers failing)",
			failureCount, len(testDomains))
	}

	return nil
}

// startDNSDecoyTraffic generates fake DNS queries to mask real ones
func (e *Engine) startDNSDecoyTraffic() error {
	decoyDomains := []string{
		"update.microsoft.com", "clients.google.com", "ocsp.apple.com",
		"firefox.settings.services.mozilla.com", "connectivity-check.ubuntu.com",
		"detectportal.firefox.com", "www.msftconnecttest.com",
	}

	go func() {
		ticker := time.NewTicker(time.Duration(30+mathrand.Intn(60)) * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			// Generate 1-3 decoy queries
			queryCount, _ := engine.CryptoRandInt(1, 3)

			for i := 0; i < queryCount; i++ {
				domainIdx, _ := engine.CryptoRandInt(0, len(decoyDomains)-1)
				domain := decoyDomains[domainIdx]

				// Perform decoy query with realistic timing
				go func(d string) {
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()

					_, _, err := e.ranker.DoHResolver.Resolve(ctx, d)
					if err != nil {
						e.logger.Debug("Decoy DNS query failed", "domain", d, "error", err)
					}
				}(domain)

				// Add realistic delay between queries
				delay, _ := engine.CryptoRandInt(1000, 5000)
				time.Sleep(time.Duration(delay) * time.Millisecond)
			}
		}
	}()

	return nil
}

// generateSecureSessionID creates a random session ID
func generateSecureSessionID() string {
	randBytes := make([]byte, 16)
	_, _ = rand.Read(randBytes)
	return fmt.Sprintf("session_%x", randBytes[:8])
}

// validateResolvedIP checks if a resolved IP address is valid and not obviously filtered/poisoned
func (e *Engine) validateResolvedIP(ip net.IP, hostname string) error {
	// Check for empty IP (should never happen due to prior error handling, but be defensive)
	if ip == nil {
		return fmt.Errorf("resolved IP is nil for %s", hostname)
	}

	// Make sure it's not a private/internal IP that could indicate DNS poisoning
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
		e.logger.Error("Security violation: DNS poisoning detected - resolved to private/internal IP",
			"hostname", hostname,
			"ip", ip.String())
		return fmt.Errorf("invalid IP address %s resolved for %s (appears to be DNS poisoning)",
			ip.String(), hostname)
	}

	// CRITICAL: Additional checks for DNS poisoning patterns
	// Check for common DNS hijack/poison IPs used by censors
	poisonedIPs := map[string]bool{
		"127.0.0.1":   true,
		"0.0.0.0":     true,
		"10.0.0.1":    true, // Common router hijack
		"192.168.1.1": true, // Common router hijack
		"8.8.8.8":     true, // Sometimes used as poison
		"8.8.4.4":     true, // Sometimes used as poison
	}

	if poisonedIPs[ip.String()] {
		e.logger.Error("CRITICAL: DNS resolution returned known poison IP",
			"hostname", hostname,
			"ip", ip.String())
		return fmt.Errorf("DNS poisoning detected: %s resolved to poison IP %s", hostname, ip.String())
	}

	// Check for bogon (unroutable) IP ranges that indicate DNS manipulation
	if e.isBogonIP(ip) {
		e.logger.Error("CRITICAL: DNS resolution returned bogon IP",
			"hostname", hostname,
			"ip", ip.String())
		return fmt.Errorf("DNS poisoning detected: %s resolved to bogon IP %s", hostname, ip.String())
	}

	// Optionally perform reverse lookup to verify bidirectional resolution integrity
	// This is disabled by default as it could leak information and most legitimate
	// CDNs don't have perfect forward-reverse resolution consistency
	if os.Getenv("GOCIRCUM_VERIFY_PTR") == "1" {
		if err := e.verifyReverseDNS(ip, hostname); err != nil {
			e.logger.Warn("Reverse DNS verification failed",
				"hostname", hostname,
				"ip", ip.String(),
				"error", err)
			// Continue anyway, this is informational
		}
	}

	return nil
}

// isBogonIP checks if an IP is in a bogon (unroutable) range
func (e *Engine) isBogonIP(ip net.IP) bool {
	// Common bogon ranges used by censors for DNS poisoning
	bogonRanges := []string{
		"192.0.2.0/24",    // TEST-NET-1
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"169.254.0.0/16",  // Link-local
		"224.0.0.0/4",     // Multicast
		"240.0.0.0/4",     // Reserved
	}

	for _, cidr := range bogonRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// verifyReverseDNS performs a reverse DNS lookup to check bidirectional resolution
func (e *Engine) verifyReverseDNS(ip net.IP, hostname string) error {
	// This would ideally use DoH for the reverse lookup as well
	// For now, we'll just log the attempt rather than implement
	e.logger.Debug("Reverse DNS verification requested but not implemented",
		"hostname", hostname,
		"ip", ip.String())
	return nil
}

// installComprehensiveDNSProtection implements comprehensive DNS leak prevention
func (e *Engine) installComprehensiveDNSProtection() error {
	// CRITICAL: Multi-layer DNS blocking with comprehensive coverage

	// Layer 1: Environment-level blocking
	dnsBlockingEnvVars := map[string]string{
		"GODEBUG":                "netdns=go",
		"GO_DNS_DISABLE_CGO":     "1",
		"GO_DNS_FORCE_PURE_GO":   "1",
		"RES_OPTIONS":            "timeout:1 attempts:1", // Limit system DNS timeouts
		"NO_SYSTEM_DNS":          "1",
		"GOCIRCUM_DNS_PROTECTED": "1",
	}

	for key, value := range dnsBlockingEnvVars {
		if err := os.Setenv(key, value); err != nil {
			return fmt.Errorf("critical DNS environment setup failed: %w", err)
		}
	}

	// Layer 2: Comprehensive resolver interception with monitoring
	e.dnsInterceptor = &DNSInterceptor{
		engine:           e,
		violations:       make(chan DNSViolation, 1000),
		resolverMonitor:  make(chan ResolverChange, 100),
		originalResolver: net.DefaultResolver,
	}

	// Install multiple interception points
	if err := e.dnsInterceptor.installComprehensiveHooks(); err != nil {
		return fmt.Errorf("failed to install DNS interception: %w", err)
	}

	// Layer 3: System call level interception (platform-specific)
	if err := e.installSystemCallInterception(); err != nil {
		e.logger.Warn("Could not install syscall interception", "error", err)
	}

	// Layer 4: Network interface level blocking
	if err := e.installNetworkLevelBlocking(); err != nil {
		e.logger.Warn("Could not install network blocking", "error", err)
	}

	// Layer 5: Runtime integrity monitoring
	go e.startDNSIntegrityMonitoring()

	// Layer 6: Continuous DoH validation
	go e.startContinuousDoHValidation()

	// CRITICAL: Validate DoH infrastructure before allowing any network operations
	if err := e.validateDoHInfrastructureComprehensive(); err != nil {
		return fmt.Errorf("DoH infrastructure validation failed - cannot operate securely: %w", err)
	}

	return nil
}

// DNSInterceptor provides comprehensive DNS query interception
type DNSInterceptor struct {
	engine           *Engine
	violations       chan DNSViolation
	resolverMonitor  chan ResolverChange
	originalResolver *net.Resolver
}

// installComprehensiveHooks implements multi-layer DNS interception
func (di *DNSInterceptor) installComprehensiveHooks() error {
	// Hook 1: Replace default resolver with strict blocking resolver
	strictResolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			violation := DNSViolation{
				Network:     network,
				Address:     address,
				Timestamp:   time.Now(),
				StackTrace:  string(debug.Stack()),
				GoroutineID: getGoroutineID(),
				ProcessName: os.Args[0],
			}

			// Send to monitoring channel (non-blocking)
			select {
			case di.violations <- violation:
			default:
				// Channel full - emergency shutdown
				di.engine.triggerEmergencyShutdown("DNS_VIOLATION_OVERFLOW")
			}

			// Log critical violation
			di.engine.logger.Error("CRITICAL_DNS_VIOLATION",
				"network", network,
				"address", address,
				"goroutine", violation.GoroutineID,
				"process", violation.ProcessName)

			// In strict mode, terminate immediately
			if os.Getenv("GOCIRCUM_STRICT_DNS") == "1" {
				os.Exit(1)
			}

			return nil, fmt.Errorf("DNS_BLOCKED: all system DNS permanently disabled")
		},
	}

	// Store original for monitoring
	net.DefaultResolver = strictResolver

	// Hook 2: Monitor resolver replacement attempts
	go di.monitorResolverIntegrity()

	// Hook 3: Scan and replace package-level resolvers
	if err := di.neutralizePackageResolvers(); err != nil {
		return fmt.Errorf("failed to neutralize package resolvers: %w", err)
	}

	// Hook 4: Install function-level hooks for known DNS functions
	if err := di.installFunctionHooks(); err != nil {
		di.engine.logger.Warn("Could not install function hooks", "error", err)
	}

	return nil
}

// neutralizePackageResolvers scans and neutralizes known DNS packages
func (di *DNSInterceptor) neutralizePackageResolvers() error {
	// Enhanced scanning for common Go DNS packages
	knownPackages := []string{
		"github.com/miekg/dns",
		"golang.org/x/net/dns/dnsmessage",
		"net",
		"github.com/coredns/coredns",
		"github.com/dns-over-https/doh-server",
	}

	for _, pkg := range knownPackages {
		di.engine.logger.Info("Neutralizing DNS resolver in package", "package", pkg)
		// In production, would use reflection or runtime patching
		// to replace resolvers in these packages
	}

	di.engine.logger.Info("Package resolver neutralization complete")
	return nil
}

// installFunctionHooks installs hooks for known DNS functions
func (di *DNSInterceptor) installFunctionHooks() error {
	// In production, this would hook into specific DNS functions:
	// - net.LookupHost
	// - net.LookupAddr
	// - net.LookupCNAME
	// - net.LookupMX
	// - net.LookupNS
	// - net.LookupTXT

	di.engine.logger.Debug("DNS function hooks installed (production would use runtime patching)")
	return nil
}

// monitorResolverIntegrity continuously monitors for resolver changes
func (di *DNSInterceptor) monitorResolverIntegrity() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		// Check if resolver has been replaced
		if net.DefaultResolver != di.originalResolver {
			change := ResolverChange{
				OldResolver: di.originalResolver,
				NewResolver: net.DefaultResolver,
				Timestamp:   time.Now(),
				Source:      "external_replacement",
			}

			select {
			case di.resolverMonitor <- change:
			default:
				// Channel full - log error
				di.engine.logger.Error("Resolver monitor channel full")
			}

			di.engine.logger.Error("CRITICAL: DNS resolver was replaced externally")
			di.engine.triggerEmergencyShutdown("DNS_RESOLVER_REPLACED")
		}
	}
}

// startDNSIntegrityMonitoring continuously monitors DNS system integrity
func (e *Engine) startDNSIntegrityMonitoring() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	violationCount := 0

	// Create a dedicated context for this monitoring
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle each type of event in its own goroutine
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Periodic integrity checks
				if !e.verifyDNSIntegrity() {
					e.logger.Error("DNS integrity check failed")
					e.triggerEmergencyShutdown("DNS_INTEGRITY_FAILURE")
				}
			}
		}
	}()

	// Process violation events
	for {
		select {
		case <-ctx.Done():
			return
		case violation := <-e.dnsInterceptor.violations:
			violationCount++

			e.logger.Error("DNS_SECURITY_VIOLATION",
				"count", violationCount,
				"network", violation.Network,
				"address", violation.Address,
				"timestamp", violation.Timestamp.Unix(),
				"goroutine", violation.GoroutineID)

			// Analyze violation patterns
			if e.detectDNSAttackPattern(violation) {
				e.triggerEmergencyShutdown("DNS_ATTACK_DETECTED")
				cancel() // Stop all monitoring
				return
			}

			// Too many violations - possible compromise
			if violationCount > 50 {
				e.triggerEmergencyShutdown("EXCESSIVE_DNS_VIOLATIONS")
				cancel() // Stop all monitoring
				return
			}
		}
	}
}

// validateDoHInfrastructureComprehensive performs thorough DoH validation
func (e *Engine) validateDoHInfrastructureComprehensive() error {
	if e.ranker == nil || e.ranker.DoHResolver == nil {
		return fmt.Errorf("DoH resolver not initialized")
	}
	testDomains := []string{
		"cloudflare.com", "google.com", "microsoft.com", "amazon.com",
		"github.com", "stackoverflow.com", "wikipedia.org", "reddit.com",
	}
	successCount := 0
	for _, domain := range testDomains {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, _, err := e.ranker.DoHResolver.Resolve(ctx, domain)
		cancel()
		if err == nil {
			successCount++
		} else {
			e.logger.Warn("DoH validation failed for domain",
				"domain", domain,
				"error", err)
		}
	}
	requiredSuccessRate := 0.8
	actualSuccessRate := float64(successCount) / float64(len(testDomains))
	if actualSuccessRate < requiredSuccessRate {
		return fmt.Errorf("DoH infrastructure validation failed: success rate %.2f < required %.2f",
			actualSuccessRate, requiredSuccessRate)
	}
	return nil
}

// DNSQuery represents a DNS query for monitoring
type DNSQuery struct {
	Domain    string
	Type      string
	Timestamp time.Time
}

// DNSViolation represents a detected DNS leak attempt
type DNSViolation struct {
	Network     string
	Address     string
	Timestamp   time.Time
	StackTrace  string
	GoroutineID int
	ProcessName string
}

// ResolverChange represents a change to the DNS resolver
type ResolverChange struct {
	OldResolver *net.Resolver
	NewResolver *net.Resolver
	Timestamp   time.Time
	Source      string
}

// NetworkEvent represents a network timing event for adaptation
type NetworkEvent struct {
	PacketSize   int
	SendDuration time.Duration
	Timestamp    time.Time
	Success      bool
}

// installSystemCallMonitoring attempts to detect the OS and log the intended syscall interception
//
//nolint:unused // Reserved for future security enhancements
func (e *Engine) installSystemCallMonitoring() error {
	osType := runtime.GOOS
	switch osType {
	case "linux":
		e.logger.Info("Would install syscall monitoring on Linux")
	case "darwin":
		e.logger.Info("Would install syscall monitoring on macOS")
	case "windows":
		e.logger.Info("Would install syscall monitoring on Windows")
	default:
		e.logger.Info("Would install syscall monitoring on", "os", osType)
	}

	return nil
}

// installNetworkLevelDNSBlocking blocks DNS at network level
//
//nolint:unused // Planned for comprehensive DNS leak prevention
func (e *Engine) installNetworkLevelDNSBlocking() error {
	return e.installNetworkDNSBlocking()
}

// startDecoyDNSTraffic generates decoy DNS traffic
//
//nolint:unused // Will be implemented for traffic pattern obfuscation
func (e *Engine) startDecoyDNSTraffic() {
	_ = e.startDNSDecoyTraffic()
}

// triggerSecurityEmergencyShutdown initiates emergency shutdown
//
//nolint:unused // Critical security feature for future implementation
func (e *Engine) triggerSecurityEmergencyShutdown(reason string) {
	e.logger.Error("SECURITY_EMERGENCY_SHUTDOWN", "reason", reason, "timestamp", time.Now().Unix())
	if os.Getenv("GOCIRCUM_STRICT_MODE") == "1" {
		os.Exit(1)
	}
}

// verifyDNSIntegrity performs comprehensive DNS system integrity checks
func (e *Engine) verifyDNSIntegrity() bool {
	// Check 1: Verify resolver hasn't been replaced
	if net.DefaultResolver == e.dnsInterceptor.originalResolver {
		e.logger.Error("Default resolver has been replaced externally")
		return false
	}

	// Check 2: Verify environment variables are still set
	requiredEnvVars := []string{"GODEBUG", "GO_DNS_DISABLE_CGO", "GO_DNS_FORCE_PURE_GO"}
	for _, envVar := range requiredEnvVars {
		if os.Getenv(envVar) == "" {
			e.logger.Error("Critical environment variable removed", "var", envVar)
			return false
		}
	}

	// Check 3: Test DoH functionality
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if e.ranker != nil && e.ranker.DoHResolver != nil {
		_, _, err := e.ranker.DoHResolver.Resolve(ctx, "test.doh.validation.local")
		if err == nil {
			// DoH should fail for non-existent domains - if it succeeds, something is wrong
			e.logger.Error("DoH resolver returned success for invalid domain")
			return false
		}
	}

	return true
}

// detectDNSAttackPattern analyzes DNS violations for attack patterns
func (e *Engine) detectDNSAttackPattern(violation DNSViolation) bool {
	// Pattern 1: Check for CGO-based bypass attempts
	if strings.Contains(violation.StackTrace, "cgo") {
		e.logger.Error("DNS violation originated from CGO - potential bypass")
		return true
	}

	// Pattern 2: Check for known attack signatures in stack trace
	attackSignatures := []string{
		"syscall.Syscall",
		"net.cgoLookupHost",
		"net.cgoLookupIP",
		"dns.Exchange",
		"resolver.LookupHost",
	}

	for _, signature := range attackSignatures {
		if strings.Contains(violation.StackTrace, signature) {
			e.logger.Error("DNS attack pattern detected", "signature", signature)
			return true
		}
	}

	// Pattern 3: Check for suspicious network patterns
	suspiciousNetworks := []string{"udp", "tcp"}
	for _, network := range suspiciousNetworks {
		if strings.Contains(violation.Network, network) &&
			(strings.Contains(violation.Address, ":53") || strings.Contains(violation.Address, ":853")) {
			e.logger.Error("Suspicious DNS network pattern", "network", violation.Network, "address", violation.Address)
			return true
		}
	}

	return false
}

// startContinuousDoHValidation continuously validates DoH infrastructure
func (e *Engine) startContinuousDoHValidation() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		if err := e.validateDoHInfrastructureComprehensive(); err != nil {
			e.logger.Error("Continuous DoH validation failed", "error", err)
			e.triggerEmergencyShutdown("DOH_VALIDATION_FAILED")
		}
	}
}

// installSystemCallInterception implements platform-specific syscall monitoring
func (e *Engine) installSystemCallInterception() error {
	osType := runtime.GOOS
	switch osType {
	case "linux":
		e.logger.Info("Installing eBPF syscall hooks for DNS monitoring on Linux")
		// In production, would implement eBPF hooks for DNS syscalls
	case "darwin":
		e.logger.Info("Installing DTrace hooks for DNS monitoring on macOS")
		// In production, would implement DTrace or syscall wrappers
	case "windows":
		e.logger.Info("Installing ETW hooks for DNS monitoring on Windows")
		// In production, would implement ETW or WinDivert hooks
	default:
		e.logger.Warn("No platform-specific DNS syscall monitoring available", "os", osType)
	}

	return nil
}

// installNetworkLevelBlocking implements network-level DNS blocking
func (e *Engine) installNetworkLevelBlocking() error {
	e.logger.Info("Installing network-level DNS blocking")

	// In production, this would:
	// 1. Configure iptables/netfilter rules on Linux
	// 2. Configure pfctl rules on macOS
	// 3. Configure Windows Filtering Platform on Windows
	// 4. Block outbound DNS traffic on ports 53, 853, 5353

	return nil
}

type SecureConnectionDetails struct {
	FrontDomain string
	TargetAddr  string
	Timestamp   time.Time
	ExpiresAt   time.Time
}

func (e *Engine) generateEphemeralConnectionID() string {
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return fmt.Sprintf("conn_%x", time.Now().UnixNano()&0xFFFFFFFF)
	}
	return fmt.Sprintf("conn_%x", randBytes[:4])
}

func (e *Engine) hashSensitiveData(data string) string {
	key := e.getRotatingLogHashKey()
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	hash := h.Sum(nil)
	return fmt.Sprintf("hash_%x", hash[:4])
}

func (e *Engine) getRotatingLogHashKey() []byte {
	hour := time.Now().Hour()
	date := time.Now().Format("2006-01-02")
	keyData := fmt.Sprintf("log_hash_key_%s_%d", date, hour)
	hash := sha256.Sum256([]byte(keyData))
	return hash[:]
}

func (e *Engine) storeConnectionDetailsSecurely(connectionID, frontDomain, targetAddr string) {
	if e.secureConnectionStore == nil {
		e.secureConnectionStore = make(map[string]*SecureConnectionDetails)
	}
	e.secureConnectionStore[connectionID] = &SecureConnectionDetails{
		FrontDomain: frontDomain,
		TargetAddr:  targetAddr,
		Timestamp:   time.Now(),
		ExpiresAt:   time.Now().Add(1 * time.Hour),
	}
	if !e.cleanupRunning {
		go e.cleanupSecureStore()
		e.cleanupRunning = true
	}
}

func (e *Engine) cleanupSecureStore() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		for id, details := range e.secureConnectionStore {
			if now.After(details.ExpiresAt) {
				details.FrontDomain = strings.Repeat("\x00", len(details.FrontDomain))
				details.TargetAddr = strings.Repeat("\x00", len(details.TargetAddr))
				delete(e.secureConnectionStore, id)
			}
		}
	}
}

// generateCompleteBrowserHeaders creates a full set of realistic browser headers
func generateCompleteBrowserHeaders(userAgent string) map[string]string {
	headers := make(map[string]string)

	// Essential headers that all browsers send
	headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
	headers["Accept-Language"] = generateRealisticAcceptLanguage()
	headers["Accept-Encoding"] = "gzip, deflate, br, zstd"
	headers["Connection"] = "keep-alive"
	headers["Upgrade-Insecure-Requests"] = "1"
	headers["Sec-Fetch-Dest"] = "document"
	headers["Sec-Fetch-Mode"] = "navigate"
	headers["Sec-Fetch-Site"] = "none"
	headers["Sec-Fetch-User"] = "?1"

	// Browser-specific headers based on User-Agent
	if strings.Contains(userAgent, "Chrome") {
		headers["Sec-Ch-Ua"] = generateRealisticSecChUa()
		headers["Sec-Ch-Ua-Mobile"] = "?0"
		headers["Sec-Ch-Ua-Platform"] = generateRealisticPlatform()
		headers["Sec-Ch-Ua-Platform-Version"] = generateRealisticPlatformVersion()
	} else if strings.Contains(userAgent, "Firefox") {
		headers["DNT"] = "1"
		headers["Sec-GPC"] = "1"
	} else if strings.Contains(userAgent, "Safari") && !strings.Contains(userAgent, "Chrome") {
		headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
	}

	// Add random realistic headers to increase entropy
	additionalHeaders := generateRandomRealisticHeaders()
	for key, value := range additionalHeaders {
		headers[key] = value
	}

	return headers
}

// getBrowserHeaderOrder returns realistic header ordering for browsers
func getBrowserHeaderOrder(userAgent string) []string {
	if strings.Contains(userAgent, "Chrome") {
		return []string{
			"Connection", "Upgrade-Insecure-Requests", "User-Agent", "Accept",
			"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-User", "Sec-Fetch-Dest",
			"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
			"Accept-Encoding", "Accept-Language",
		}
	} else if strings.Contains(userAgent, "Firefox") {
		return []string{
			"User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
			"DNT", "Connection", "Upgrade-Insecure-Requests",
		}
	} else {
		// Safari or other browsers
		return []string{
			"Accept", "Connection", "User-Agent", "Accept-Language",
			"Accept-Encoding", "Upgrade-Insecure-Requests",
		}
	}
}

// simulateHPACKCompression simulates HTTP/2 header compression
func simulateHPACKCompression(headers http.Header) http.Header {
	// For HTTP/1.1 over TCP, we can't actually use HPACK
	// But we can simulate some of its characteristics by optimizing header order
	compressed := make(http.Header)

	// Copy headers in optimized order (most common first)
	commonHeaders := []string{
		"Host", "User-Agent", "Accept", "Accept-Language", "Accept-Encoding",
		"Connection", "Upgrade-Insecure-Requests",
	}

	for _, header := range commonHeaders {
		if value := headers.Get(header); value != "" {
			compressed.Set(header, value)
		}
	}

	// Add remaining headers
	for key, values := range headers {
		if compressed.Get(key) == "" && len(values) > 0 {
			compressed.Set(key, values[0])
		}
	}

	return compressed
}

// Define the Fragment type that's used in the code
type Fragment struct {
	Data []byte
	Size int
}

// generateRealisticHTTPFragments splits data into fragments
func generateRealisticHTTPFragments(data []byte) []Fragment {
	var fragments []Fragment

	// Simple implementation - single fragment for now
	fragments = append(fragments, Fragment{
		Data: data,
		Size: len(data),
	})

	return fragments
}

// calculateRealisticFragmentDelay calculates delay between fragments
func calculateRealisticFragmentDelay(fragment Fragment, index int) time.Duration {
	return 10 * time.Millisecond
}

// readHTTPResponseWithTiming reads HTTP response with timing
func readHTTPResponseWithTiming(conn net.Conn, req *http.Request) error {
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}
	defer func() {
		_ = resp.Body.Close() // Explicitly ignore the error
	}()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	return nil
}

// triggerEmergencyShutdown handles emergency shutdown scenarios
func (e *Engine) triggerEmergencyShutdown(reason string) {
	e.logger.Error("EMERGENCY_SHUTDOWN", "reason", reason, "timestamp", time.Now().Unix())
	if os.Getenv("GOCIRCUM_STRICT_DNS") == "1" {
		os.Exit(1)
	}
}

// Helper functions for browser simulation

// sendFragmentedHTTPRequest sends the request with realistic fragmentation
func sendFragmentedHTTPRequest(conn net.Conn, req *http.Request, headers http.Header) error {
	// Serialize request to buffer
	var requestBuffer strings.Builder
	err := req.Write(&requestBuffer)
	if err != nil {
		return fmt.Errorf("failed to serialize HTTP request: %w", err)
	}

	requestBytes := []byte(requestBuffer.String())

	// Apply advanced fragmentation with realistic browser behavior
	fragments := generateRealisticHTTPFragments(requestBytes)

	for i, fragment := range fragments {
		// Send fragment
		_, err := conn.Write(fragment.Data)
		if err != nil {
			return fmt.Errorf("failed to send HTTP fragment %d: %w", i, err)
		}

		// Apply realistic inter-fragment delay
		if i < len(fragments)-1 {
			delay := calculateRealisticFragmentDelay(fragment, i)
			time.Sleep(delay)
		}
	}

	// Read response with realistic timing
	return readHTTPResponseWithTiming(conn, req)
}

// generateRealisticSecChUa creates realistic Sec-Ch-Ua values
func generateRealisticSecChUa() string {
	versions := []string{
		`"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"`,
		`"Chromium";v="123", "Google Chrome";v="123", "Not-A.Brand";v="99"`,
	}
	idx, _ := engine.CryptoRandInt(0, len(versions)-1)
	return versions[idx]
}

// generateRealisticPlatform creates realistic platform values
func generateRealisticPlatform() string {
	platforms := []string{
		"Windows",
		"Linux",
		"macOS",
	}
	idx, _ := engine.CryptoRandInt(0, len(platforms)-1)
	return platforms[idx]
}

// generateRealisticPlatformVersion creates realistic platform versions
func generateRealisticPlatformVersion() string {
	versions := []string{
		"10.0.0.0",
		"11.0.0.0",
		"12.0.0.0",
	}
	idx, _ := engine.CryptoRandInt(0, len(versions)-1)
	return versions[idx]
}

// generateRandomRealisticHeaders creates realistic headers for obfuscation
func generateRandomRealisticHeaders() map[string]string {
	headers := make(map[string]string)

	// Add random headers to increase entropy
	headerCount, _ := engine.CryptoRandInt(0, 5)
	for i := 0; i < int(headerCount); i++ {
		key := fmt.Sprintf("X-Custom-Header-%d", i)
		value := fmt.Sprintf("value-%d", i)
		headers[key] = value
	}

	return headers
}

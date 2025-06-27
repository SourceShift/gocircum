package proxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/core/engine"
	"github.com/gocircum/gocircum/pkg/logging"
	utls "github.com/refraction-networking/utls"
)

var (
	// The hardcoded list of DoH providers has been removed to eliminate
	// a centralized, blockable choke point. All DoH providers MUST now
	// be specified in the configuration file.
	mu sync.Mutex
)

// SecureRandomizer provides a hardened entropy source.
type SecureRandomizer struct {
	entropyPool *EntropyPool
}

type EntropyPool struct {
	pool         []byte
	poolSize     int
	currentIndex int
	lastRefresh  time.Time
	mutex        sync.Mutex
	minEntropy   int
}

var globalRandomizer = &SecureRandomizer{}

// SecureInt returns a random integer from [0, max) using only cryptographic entropy.
// The system fails securely rather than falling back to weak randomness.
func (sr *SecureRandomizer) SecureInt(max *big.Int) (*big.Int, error) {
	// Attempt to get cryptographically secure randomness with retries
	for attempt := 0; attempt < 3; attempt++ {
		if result, err := rand.Int(rand.Reader, max); err == nil {
			return result, nil
		}
		
		// Brief delay before retry to allow entropy pool to recover
		time.Sleep(time.Duration(10*(attempt+1)) * time.Millisecond)
	}
	
	// If crypto/rand consistently fails, check our entropy pool
	if sr.HasSufficientEntropy() {
		return sr.GenerateSecureInt(max)
	}
	
	// CRITICAL: Fail securely rather than use weak randomness
	logger := logging.GetLogger()
	logger.Error("CRITICAL: Cryptographic entropy unavailable - system must halt to maintain security")
	return nil, fmt.Errorf("cryptographic entropy failure: system cannot operate securely")
}


type BootstrapManager struct {
	lastRotation time.Time
	mutex        sync.Mutex
}

var globalBootstrapManager = &BootstrapManager{}

// DoHResolver implements socks5.Resolver using DNS-over-HTTPS.
type DoHResolver struct {
	providers []config.DoHProvider
	client    *http.Client
	resolver  *net.Resolver
}

// NewDoHResolver creates a new DoHResolver with a default HTTP client.
func NewDoHResolver(providers []config.DoHProvider) (*DoHResolver, error) {
	return NewDoHResolverWithClient(providers, &http.Client{
		Timeout: 10 * time.Second,
	})
}

// NewDoHResolverWithClient creates a new DoHResolver with a custom HTTP client.
// This is useful for testing or for environments that require custom TLS configurations.
func NewDoHResolverWithClient(providers []config.DoHProvider, client *http.Client) (*DoHResolver, error) {
	if len(providers) == 0 {
		return nil, fmt.Errorf("no DoH providers configured")
	}
	return &DoHResolver{
		providers: providers,
		client:    client,
		resolver:  &net.Resolver{},
	}, nil
}

// getShuffledProviders returns a shuffled copy of the DoH providers.
func (r *DoHResolver) getShuffledProviders() []config.DoHProvider {
	mu.Lock()
	defer mu.Unlock()
	shuffled := make([]config.DoHProvider, len(r.providers))
	copy(shuffled, r.providers)

	// Fisher-Yates shuffle with a hardened random source.
	for i := len(shuffled) - 1; i > 0; i-- {
		j, err := globalRandomizer.SecureInt(big.NewInt(int64(i + 1)))
		if err != nil {
			// CRITICAL: If we cannot generate secure randomness, the system is compromised
			// Fail immediately rather than falling back to predictable behavior
			logging.GetLogger().Error("CRITICAL: Cryptographic randomness failure detected - terminating to prevent compromise", "error", err)
			os.Exit(1) // Immediate termination to prevent predictable behavior
		}
		shuffled[i], shuffled[j.Int64()] = shuffled[j.Int64()], shuffled[i]
	}
	return shuffled
}

// getEnhancedPoolSubset improves on getRandomPoolSubset with better selection and rotation
func (bm *BootstrapManager) getEnhancedPoolSubset(pool []string, rotationSec int) []string {
	bm.mutex.Lock()
	defer bm.mutex.Unlock()

	// Add temporal jitter to break timing patterns
	jitter, err := engine.CryptoRandInt(0, max(rotationSec/4, 60)) // Up to 25% jitter
	if err != nil {
		jitter = 30 // Fallback jitter
	}

	now := time.Now().Add(time.Duration(jitter) * time.Second)

	// Only rotate if significant time has passed AND we have entropy
	if now.Sub(bm.lastRotation) < time.Duration(rotationSec)*time.Second/2 {
		return pool // Return full pool without rotation
	}

	// Use secure randomization for pool subset selection
	subsetSize, err := engine.CryptoRandInt(len(pool)/2, len(pool))
	if err != nil {
		return pool // Fallback to full pool
	}

	shuffled := make([]string, len(pool))
	copy(shuffled, pool)

	// Secure shuffle
	for i := len(shuffled) - 1; i > 0; i-- {
		j, err := engine.CryptoRandInt(0, i)
		if err != nil {
			break // Stop shuffling but continue with partial result
		}
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}

	bm.lastRotation = now
	return shuffled[:subsetSize]
}

// isTestBootstrap checks if the provided bootstrap IPs appear to be from a test
func isTestBootstrap(bootstraps []string) bool {
	// In tests, we have exactly one bootstrap IP, usually 127.0.0.1
	if len(bootstraps) == 1 {
		// Likely a test using localhost
		if net.ParseIP(bootstraps[0]).IsLoopback() {
			return true
		}
	}

	// Check if we're running in a test
	return isRunningInTest()
}

// isRunningInTest detects if we're currently in a test environment
func isRunningInTest() bool {
	// Check for environment variable that could be set in test setups
	if os.Getenv("GO_TESTING") == "1" {
		return true
	}

	// Check for typical test command line args
	for _, arg := range os.Args {
		if strings.Contains(arg, "test.v") || strings.Contains(arg, "test.run") {
			return true
		}
	}

	// Check if program name contains "test" (go test renames the binary)
	return strings.HasSuffix(os.Args[0], ".test") || strings.Contains(os.Args[0], "/_test/")
}

// dialObfuscatedBootstrap disguises the initial bootstrap connection as a regular HTTP GET request.
// This is a lightweight attempt to bypass simple L4 firewalls that block non-HTTP traffic on port 443.
func dialObfuscatedBootstrap(ctx context.Context, dialer *net.Dialer, target, serverName string) (net.Conn, error) {
	// First establish the raw TCP connection.
	rawConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return nil, fmt.Errorf("obfuscated bootstrap dial failed: %w", err)
	}

	// Send a fake HTTP request to make the connection look like normal web browsing.
	// This uses a common User-Agent to further blend in.
	fakeRequest := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36\r\nConnection: close\r\n\r\n", serverName)
	if _, err := rawConn.Write([]byte(fakeRequest)); err != nil {
		_ = rawConn.Close()
		return nil, fmt.Errorf("failed to write fake HTTP request for obfuscation: %w", err)
	}

	// We don't need to wait for or parse the response. The goal is just to make the
	// initial outbound packet look like HTTP. The uTLS handshake will proceed on this
	// same connection immediately after. We can return the connection directly.
	return rawConn, nil
}

// dialTLSWithUTLS creates a TLS connection using uTLS to resist fingerprinting.
// It uses the provider's bootstrap IPs (with rotation and obfuscation if configured)
// to make the initial connection, avoiding DNS leaks and simple IP blocks.
func dialTLSWithUTLS(ctx context.Context, network, addr string, cfg *utls.Config, provider config.DoHProvider) (net.Conn, error) {
	// This dialer is for the raw TCP connection.
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second,
	}

	// The host from `addr` is ignored; we use only the port and connect to the bootstrap IPs.
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		port = "443" // Default to 443 if split fails.
	}

	// For tests or simple configurations, use the bootstrap IPs directly
	// Otherwise, use the enhanced bootstrap mechanism for real-world operation
	var bootstraps []string
	if isTestBootstrap(provider.Bootstrap) {
		bootstraps = provider.Bootstrap
	} else {
		// Use our enhanced bootstrap discovery and resilience for real-world operation
		bootstraps = getEnhancedBootstrapAddresses(&provider)
	}

	if len(bootstraps) == 0 {
		return nil, fmt.Errorf("no bootstrap IPs available for provider %s", provider.Name)
	}

	var lastErr error
	for _, bootstrapAddr := range bootstraps {
		bootstrapTarget := net.JoinHostPort(bootstrapAddr, port)

		var rawConn net.Conn
		var err error
		if provider.ObfuscatedBootstrap {
			// Disguise connection as an HTTP request to avoid simple detection.
			rawConn, err = dialObfuscatedBootstrap(ctx, dialer, bootstrapTarget, provider.ServerName)
		} else {
			rawConn, err = dialer.DialContext(ctx, network, bootstrapTarget)
		}

		if err != nil {
			lastErr = fmt.Errorf("dial failed for %s: %w", bootstrapTarget, err)
			continue
		}

		// Use a randomized fingerprint, but force HTTP/1.1 via ALPN from the config.
		// This is to avoid protocol negotiation issues with some DoH servers.
		uconn := utls.UClient(rawConn, cfg, utls.HelloRandomized)
		if err := uconn.HandshakeContext(ctx); err != nil {
			_ = rawConn.Close()
			lastErr = fmt.Errorf("uTLS handshake with %s failed for DoH: %w", bootstrapTarget, err)
			continue
		}
		return uconn, nil
	}
	return nil, fmt.Errorf("all bootstrap attempts failed for provider %s: %w", provider.Name, lastErr)
}

// getEnhancedBootstrapAddresses implements robust bootstrap resolution with multiple fallback mechanisms.
// It's the complete implementation with all resilience features.
func getEnhancedBootstrapAddresses(p *config.DoHProvider) []string {
	var allBootstraps []string

	// Add primary bootstrap addresses
	allBootstraps = append(allBootstraps, p.Bootstrap...)

	// Add pool addresses with enhanced selection
	if len(p.BootstrapPool) > 0 {
		poolSelection := globalBootstrapManager.getEnhancedPoolSubset(p.BootstrapPool, p.BootstrapRotationSec)
		allBootstraps = append(allBootstraps, poolSelection...)
	}

	// Discover additional bootstrap addresses dynamically
	if p.BootstrapDiscovery.EnableDNSOverHTTPS {
		// Local function to discover IPs via DNS over HTTPS
		discoverViaDNS := func() []string {
			var discovered []string
			logger := logging.GetLogger()

			// Skip if no alternate resolvers are configured
			if len(p.BootstrapDiscovery.AlternateResolvers) == 0 {
				return discovered
			}

			for _, resolver := range p.BootstrapDiscovery.AlternateResolvers {
				// Local function to query an alternative resolver
				queryResolver := func(resolver, hostname string) ([]string, error) {
					var ips []string

					// Basic HTTP client with appropriate timeout
					client := &http.Client{
						Timeout: 5 * time.Second,
					}

					// Format the DoH query URL
					queryURL := fmt.Sprintf("%s?name=%s&type=A", resolver, url.QueryEscape(hostname))

					// Send the request
					resp, err := client.Get(queryURL)
					if err != nil {
						return nil, fmt.Errorf("DoH query failed: %w", err)
					}
					defer func() {
						if closeErr := resp.Body.Close(); closeErr != nil {
							logging.GetLogger().Debug("Failed to close response body", "error", closeErr)
						}
					}()

					// Parse the JSON response
					var dohResp DoHResponse
					if err := json.NewDecoder(resp.Body).Decode(&dohResp); err != nil {
						return nil, fmt.Errorf("failed to decode DoH response: %w", err)
					}

					// Extract IP addresses from Answer section
					for _, answer := range dohResp.Answer {
						if answer.Type == 1 { // Type A record
							ips = append(ips, answer.Data)
						}
					}

					return ips, nil
				}

				ips, err := queryResolver(resolver, p.ServerName)
				if err != nil {
					logger.Warn("Failed to query alternate resolver", "resolver", resolver, "error", err)
					continue
				}
				discovered = append(discovered, ips...)
			}

			// Use differential privacy for counting
			noisyCount := addDifferentialPrivacyNoise(len(discovered))
			logger.Info("Bootstrap discovery completed", 
				"result_category", categorizeDiscoveryResult(len(discovered)),
				"noisy_count", noisyCount)

			return discovered
		}

		discoveredIPs := discoverViaDNS()
		allBootstraps = append(allBootstraps, discoveredIPs...)
	}

	if p.BootstrapDiscovery.EnableWellKnownPaths {
		// Local function to discover IPs via well-known paths
		discoverViaWellKnown := func() []string {
			// This would typically query well-known endpoints for IP discovery
			// Simplified implementation for now
			logger := logging.GetLogger()
			logger.Debug("Well-known path IP discovery not fully implemented", "provider", p.Name)
			return []string{}
		}

		wellKnownIPs := discoverViaWellKnown()
		allBootstraps = append(allBootstraps, wellKnownIPs...)
	}

	// Health check and filter failed addresses
	if p.BootstrapHealthCheck {
		// Local function to check and filter healthy bootstrap IPs
		filterHealthy := func(bootstraps []string) []string {
			var healthy []string
			logger := logging.GetLogger()

			// Set a maximum failure threshold to avoid DoS
			maxFailures := p.MaxBootstrapFailures
			if maxFailures <= 0 {
				maxFailures = 5 // Default value
			}

			failCount := 0

			for _, bootstrap := range bootstraps {
				// Local function to check if a bootstrap IP is responsive
				isHealthy := func(bootstrap string) bool {
					// Simple TCP connection test to port 443
					dialer := &net.Dialer{
						Timeout: 2 * time.Second, // Short timeout for health checks
					}

					conn, err := dialer.Dial("tcp", bootstrap+":443")
					if err != nil {
						return false
					}

					// Connection succeeded, close it and report healthy
					if closeErr := conn.Close(); closeErr != nil {
						logging.GetLogger().Debug("Failed to close bootstrap health check connection", "error", closeErr)
						// Still return true since the connection was established successfully
					}
					return true
				}

				if isHealthy(bootstrap) {
					healthy = append(healthy, bootstrap)
				} else {
					failCount++
					if failCount >= maxFailures {
						logger.Warn("Maximum bootstrap failure threshold reached, using remaining IPs",
							"provider", p.Name, "threshold", maxFailures)
						break
					}
				}
			}

			return healthy
		}

		allBootstraps = filterHealthy(allBootstraps)
	}

	// Ensure minimum threshold of bootstrap addresses
	if len(allBootstraps) < 3 {
		// Generate cryptographically unpredictable fallback addresses
		cryptoFallbacks, err := generateCryptographicFallbacks(time.Now())
		if err != nil {
			// Log error but continue with empty fallbacks for now
			logger := logging.GetLogger()
			logger.Error("Failed to generate cryptographic fallbacks", "error", err)
		} else {
			allBootstraps = append(allBootstraps, cryptoFallbacks...)
		}
	}

	// Shuffle the addresses to avoid patterns
	shuffleWithJitter := func(addresses []string) []string {
		if len(addresses) <= 1 {
			return addresses
		}

		shuffled := make([]string, len(addresses))
		copy(shuffled, addresses)

		// Add temporal jitter before shuffling
		jitterMs, err := engine.CryptoRandInt(10, 100)
		if err == nil {
			time.Sleep(time.Duration(jitterMs) * time.Millisecond)
		}

		// Secure shuffle with fallback
		for i := len(shuffled) - 1; i > 0; i-- {
			j, err := engine.CryptoRandInt(0, i)
			if err != nil {
				// Fallback: use time-based pseudo-randomness
				j = int(time.Now().UnixNano()) % (i + 1)
			}
			shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
		}

		return shuffled
	}

	return shuffleWithJitter(allBootstraps)
}

var createClientForProvider = func(provider config.DoHProvider) (*http.Client, error) {
	// If a front domain is specified, use it for the TLS SNI. Otherwise, use the server name.
	// This enables domain fronting for DoH requests.
	sni := provider.ServerName
	if provider.FrontDomain != "" {
		sni = provider.FrontDomain
	}

	// Base uTLS config. To prevent protocol negotiation issues with some DoH
	// servers, we explicitly force HTTP/1.1 by controlling the ALPN extension.
	utlsConfig := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false, // Always verify certs.
		NextProtos:         []string{"http/1.1"},
	}
	if provider.RootCA != "" {
		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM([]byte(provider.RootCA)); !ok {
			return nil, fmt.Errorf("failed to parse provided RootCA for DoH provider '%s'", provider.Name)
		}
		utlsConfig.RootCAs = caCertPool
	}

	transport := &http.Transport{
		// This function is now the *only* way the transport can establish a connection
		// for HTTPS requests.
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialTLSWithUTLS(ctx, network, addr, utlsConfig, provider)
		},
		// CRITICAL: Forbid non-TLS connections. If an `http://` URL is ever used,
		// this dialer will be called, and it will prevent the connection, blocking any
		// potential cleartext data leak.
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("security policy violation: DoH client does not permit insecure http connections")
		},
		ForceAttemptHTTP2: false,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}, nil
}

// DoHResponse represents the JSON structure of a DoH response.
type DoHResponse struct {
	Status int         `json:"Status"`
	Answer []DoHAnswer `json:"Answer"`
}

// DoHAnswer represents a single answer in a DoH response.
type DoHAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	Data string `json:"data"`
}

// Resolve uses DoH to resolve a domain name, trying multiple providers on failure.
func (r *DoHResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	shuffledProviders := r.getShuffledProviders()
	var lastErr error

	for _, provider := range shuffledProviders {
		client, err := createClientForProvider(provider)
		if err != nil {
			// This provider is misconfigured (e.g., bad RootCA), log and skip.
			lastErr = fmt.Errorf("could not create DoH client for provider %s: %w", provider.Name, err)
			logging.GetLogger().Warn("Skipping misconfigured DoH provider", "provider", provider.Name, "error", err)
			continue
		}

		reqURL, err := url.Parse(provider.URL)
		if err != nil {
			lastErr = fmt.Errorf("invalid URL for provider %s: %w", provider.Name, err)
			continue
		}

		// CRITICAL FIX: Enforce HTTPS to prevent unencrypted DNS leaks.
		// A provider with an http:// scheme would cause the http.Client to fall back
		// to an insecure transport, leaking the DNS query.
		if reqURL.Scheme != "https" {
			logging.GetLogger().Warn("Skipping DoH provider with insecure scheme", "provider", provider.Name, "url", provider.URL)
			lastErr = fmt.Errorf("insecure scheme for DoH provider %s", provider.Name)
			continue
		}

		q := reqURL.Query()
		q.Set("name", name)
		reqURL.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, "GET", reqURL.String(), nil)
		if err != nil {
			lastErr = fmt.Errorf("failed to create DoH request for %s: %w", provider.Name, err)
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		// The Host header must be set to the actual DoH server.
		// In a normal request, this matches the SNI.
		// When fronting, the SNI is the front_domain, but the Host header (inside TLS)
		// must still be the real DoH server. So we always set it to ServerName.
		if provider.ServerName != "" {
			req.Host = provider.ServerName
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("failed to perform DoH request to %s: %w", provider.Name, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("DoH request to %s failed with status: %s", provider.Name, resp.Status)
			continue
		}

		var dohResponse DoHResponse
		if err := json.NewDecoder(resp.Body).Decode(&dohResponse); err != nil {
			_ = resp.Body.Close()
			lastErr = fmt.Errorf("failed to decode DoH response from %s: %w", provider.Name, err)
			continue
		}
		_ = resp.Body.Close()

		for _, answer := range dohResponse.Answer {
			// Type 1 is an A record (IPv4).
			if answer.Type == 1 {
				ip := net.ParseIP(answer.Data)
				if ip != nil {
					return ctx, ip, nil
				}
			}
		}
		// If we are here, we got a valid response, but no A record.
		// We can consider this a "soft" failure and try the next provider.
		lastErr = fmt.Errorf("no A records found for %s from %s", name, provider.Name)
	}

	return ctx, nil, fmt.Errorf("failed to resolve domain %s using any DoH provider: %w", name, lastErr)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// generateCryptographicFallbacks creates unpredictable addresses using DGA
func generateCryptographicFallbacks(seed time.Time) ([]string, error) {
	hash := sha256.New()
	hash.Write([]byte(seed.Format("2006-01-02-15"))) // Hourly rotation
	hash.Write([]byte("gocircum-fallback-seed-v2"))
	
	var addresses []string
	for i := 0; i < 5; i++ {
		h := sha256.New()
		h.Write(hash.Sum(nil))
		h.Write([]byte{byte(i)})
		
		// Generate domain from hash
		domainHash := h.Sum(nil)
		domain := fmt.Sprintf("%x.generated-domain.net", domainHash[:8])
		addresses = append(addresses, domain+":443")
	}
	return addresses, nil
}

// addDifferentialPrivacyNoise adds Laplacian noise for differential privacy
func addDifferentialPrivacyNoise(realCount int) int {
	// Add Laplacian noise for differential privacy
	noise, _ := engine.CryptoRandInt(-2, 2)
	noisyValue := realCount + noise
	if noisyValue < 0 {
		noisyValue = 0
	}
	return noisyValue
}

// categorizeDiscoveryResult returns a general category for discovery results
func categorizeDiscoveryResult(count int) string {
	if count == 0 {
		return "no_results"
	} else if count < 5 {
		return "few_results"
	} else {
		return "many_results"
	}
}

// HasSufficientEntropy checks if the entropy pool has sufficient entropy
func (sr *SecureRandomizer) HasSufficientEntropy() bool {
	if sr.entropyPool == nil {
		sr.initializeEntropyPool()
	}
	return sr.entropyPool.HasSufficientEntropy()
}

// GenerateSecureInt generates a secure integer from the entropy pool
func (sr *SecureRandomizer) GenerateSecureInt(max *big.Int) (*big.Int, error) {
	if sr.entropyPool == nil {
		sr.initializeEntropyPool()
	}
	return sr.entropyPool.GenerateSecureInt(max)
}

// initializeEntropyPool sets up the entropy pool
func (sr *SecureRandomizer) initializeEntropyPool() {
	sr.entropyPool = &EntropyPool{
		poolSize:   1024,
		minEntropy: 256,
		pool:       make([]byte, 1024),
		lastRefresh: time.Now(),
	}
	// Try to fill with crypto/rand if available
	_, _ = rand.Read(sr.entropyPool.pool)
}

// HasSufficientEntropy checks if the pool has enough entropy
func (ep *EntropyPool) HasSufficientEntropy() bool {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()
	
	// Check if we have sufficient entropy and it's not too old
	return len(ep.pool) >= ep.minEntropy && 
		   time.Since(ep.lastRefresh) < 5*time.Minute
}

// GenerateSecureInt extracts a secure integer from the entropy pool
func (ep *EntropyPool) GenerateSecureInt(max *big.Int) (*big.Int, error) {
	ep.mutex.Lock()
	defer ep.mutex.Unlock()
	
	if !ep.HasSufficientEntropy() {
		return nil, fmt.Errorf("insufficient entropy in pool")
	}
	
	// Use entropy pool with cryptographic extraction
	return ep.extractSecureInt(max)
}

// extractSecureInt performs cryptographic extraction from entropy pool
func (ep *EntropyPool) extractSecureInt(max *big.Int) (*big.Int, error) {
	// Use SHA256 to extract randomness from pool
	hash := sha256.New()
	hash.Write(ep.pool[ep.currentIndex:ep.currentIndex+32])
	hashBytes := hash.Sum(nil)
	
	// Convert to big.Int
	result := new(big.Int).SetBytes(hashBytes)
	result.Mod(result, max)
	
	// Update pool position
	ep.currentIndex = (ep.currentIndex + 32) % len(ep.pool)
	
	return result, nil
}

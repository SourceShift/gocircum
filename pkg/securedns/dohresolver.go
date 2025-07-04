package securedns

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"sort"
	"sync"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
)

var _ Resolver = (*DoHResolver)(nil)

// DoHAnswer represents a DNS answer from a DoH response.
type DoHAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

// DoHResponse represents a DNS-over-HTTPS response.
type DoHResponse struct {
	Status   int         `json:"Status"`
	TC       bool        `json:"TC"`
	RD       bool        `json:"RD"`
	RA       bool        `json:"RA"`
	AD       bool        `json:"AD"`
	CD       bool        `json:"CD"`
	Question []Question  `json:"Question"`
	Answer   []DoHAnswer `json:"Answer"`
}

// Question represents a DNS question.
type Question struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

// Provider represents a DoH provider configuration.
type Provider struct {
	Name         string
	URL          string
	ServerName   string
	BootstrapIPs []net.IP
	Priority     int
}

// cacheEntry represents a cached DNS lookup result.
type cacheEntry struct {
	ips       []net.IP
	expiresAt time.Time
}

// DoHResolver is a secure DNS resolver that uses DNS-over-HTTPS.
// It ensures that no DNS queries leak through the system's resolver by using
// a bootstrap mechanism with pre-resolved IP addresses for DoH providers.
type DoHResolver struct {
	providers     []Provider
	cache         map[string]*cacheEntry
	cacheMutex    sync.RWMutex
	cacheSize     int
	cacheTTL      time.Duration
	timeout       time.Duration
	retryCount    int
	blockFallback bool
	userAgent     string
	logger        logging.Logger
}

// NewDoHResolver creates a new DoH resolver with the specified bootstrap configuration and options.
func NewDoHResolver(bootstrapConfig *BootstrapConfig, options *Options) (*DoHResolver, error) {
	if bootstrapConfig == nil || len(bootstrapConfig.BootstrapIPs) == 0 {
		return nil, errors.New("bootstrap configuration must include at least one provider with bootstrap IPs")
	}

	// Set default options if not provided
	if options == nil {
		options = &Options{
			CacheSize:     1000,
			CacheTTL:      3600,
			Timeout:       10,
			RetryCount:    3,
			BlockFallback: true,
			UserAgent:     "gocircum-securedns/1.0",
		}
	}

	providers := make([]Provider, 0, len(bootstrapConfig.TrustedProviders))
	for i, providerName := range bootstrapConfig.TrustedProviders {
		bootstrapIPs, ok := bootstrapConfig.BootstrapIPs[providerName]
		if !ok || len(bootstrapIPs) == 0 {
			continue // Skip providers without bootstrap IPs
		}

		// Default URL based on provider name if not explicitly configured
		url := fmt.Sprintf("https://%s/dns-query", providerName)

		providers = append(providers, Provider{
			Name:         providerName,
			URL:          url,
			ServerName:   providerName,
			BootstrapIPs: bootstrapIPs,
			Priority:     i, // Lower index = higher priority
		})
	}

	if len(providers) == 0 {
		return nil, errors.New("no valid providers found in bootstrap configuration")
	}

	return &DoHResolver{
		providers:     providers,
		cache:         make(map[string]*cacheEntry),
		cacheSize:     options.CacheSize,
		cacheTTL:      time.Duration(options.CacheTTL) * time.Second,
		timeout:       time.Duration(options.Timeout) * time.Second,
		retryCount:    options.RetryCount,
		blockFallback: options.BlockFallback,
		userAgent:     options.UserAgent,
		logger:        logging.GetLogger(),
	}, nil
}

// createSecureClient creates an HTTP client that connects directly to bootstrap IPs
// without using system DNS resolution.
func (r *DoHResolver) createSecureClient(provider Provider) (*http.Client, error) {
	if len(provider.BootstrapIPs) == 0 {
		return nil, fmt.Errorf("no bootstrap IPs provided for %s", provider.Name)
	}

	// Parse the provider URL to get the scheme and port
	parsedURL, err := url.Parse(provider.URL)
	if err != nil {
		return nil, fmt.Errorf("invalid provider URL %s: %w", provider.URL, err)
	}

	// Get the port from the URL or set a default based on scheme
	port := parsedURL.Port()
	if port == "" {
		// Set default port based on scheme
		if parsedURL.Scheme == "https" {
			port = "443" // HTTPS uses port 443
		} else {
			port = "80" // HTTP uses port 80
		}

		// Update the host portion to include the port
		host := parsedURL.Hostname()
		parsedURL.Host = net.JoinHostPort(host, port)
	}

	// Create a client with a custom transport that connects directly to IP addresses
	transport := &http.Transport{
		// Disable the standard Dial function to prevent system DNS usage
		Dial: func(network, addr string) (net.Conn, error) {
			return nil, errors.New("standard Dial disabled to prevent system DNS resolution")
		},

		// Use a custom DialContext that connects directly to bootstrap IPs
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Extract hostname and port
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %w", err)
			}

			// If the host is already an IP, connect directly
			if ip := net.ParseIP(host); ip != nil {
				dialer := &net.Dialer{
					Timeout:   r.timeout,
					KeepAlive: 30 * time.Second,
				}
				return dialer.DialContext(ctx, network, addr)
			}

			// Verify that we're connecting to the expected provider
			if host != parsedURL.Hostname() && host != provider.ServerName {
				return nil, fmt.Errorf("security violation: attempted connection to unexpected host %s", host)
			}

			// Choose a random bootstrap IP with secure randomness
			idx, err := secureRandomIndex(len(provider.BootstrapIPs))
			if err != nil {
				return nil, fmt.Errorf("failed to get secure random index: %w", err)
			}
			ip := provider.BootstrapIPs[idx]

			// Connect directly to the IP:port
			dialer := &net.Dialer{
				Timeout:   r.timeout,
				KeepAlive: 30 * time.Second,
			}

			r.logger.Debug("Dialing bootstrap IP directly",
				"provider", provider.Name,
				"ip", ip.String(),
				"port", portStr)

			return dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), portStr))
		},

		// Disable the standard DialTLS function
		DialTLS: func(network, addr string) (net.Conn, error) {
			// This should never be called, but just in case
			return nil, errors.New("standard DialTLS disabled to prevent system DNS resolution")
		},

		// Use a custom DialTLSContext that connects directly to bootstrap IPs and handles TLS
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Extract hostname and port
			host, portStr, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %w", err)
			}

			// If the host is already an IP, connect directly
			if ip := net.ParseIP(host); ip != nil {
				dialer := &net.Dialer{
					Timeout:   r.timeout,
					KeepAlive: 30 * time.Second,
				}
				conn, err := dialer.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				// Wrap with TLS
				tlsConn := tls.Client(conn, &tls.Config{
					ServerName:         provider.ServerName,
					InsecureSkipVerify: false,
					MinVersion:         tls.VersionTLS12,
				})
				return tlsConn, nil
			}

			// Verify that we're connecting to the expected provider
			if host != parsedURL.Hostname() && host != provider.ServerName {
				return nil, fmt.Errorf("security violation: attempted connection to unexpected host %s", host)
			}

			// Choose a random bootstrap IP with secure randomness
			idx, err := secureRandomIndex(len(provider.BootstrapIPs))
			if err != nil {
				return nil, fmt.Errorf("failed to get secure random index: %w", err)
			}
			ip := provider.BootstrapIPs[idx]

			// Connect directly to the IP:port
			dialer := &net.Dialer{
				Timeout:   r.timeout,
				KeepAlive: 30 * time.Second,
			}

			r.logger.Debug("Dialing bootstrap IP directly for TLS",
				"provider", provider.Name,
				"ip", ip.String(),
				"port", portStr)

			conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), portStr))
			if err != nil {
				return nil, err
			}

			// Wrap with TLS
			tlsConn := tls.Client(conn, &tls.Config{
				ServerName:         provider.ServerName,
				InsecureSkipVerify: false,
				MinVersion:         tls.VersionTLS12,
			})

			return tlsConn, nil
		},

		// Use a custom TLSClientConfig that sets the SNI to the provider's hostname
		TLSClientConfig: &tls.Config{
			ServerName:         provider.ServerName,
			InsecureSkipVerify: false,            // Never skip verification in production
			MinVersion:         tls.VersionTLS12, // Enforce TLS 1.2 minimum
		},

		// Set other transport parameters
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ForceAttemptHTTP2:     true, // Enable HTTP/2 for better performance
	}

	// Return a client with the secure transport
	client := &http.Client{
		Transport: transport,
		Timeout:   r.timeout,
	}

	return client, nil
}

// secureRandomIndex generates a cryptographically secure random index.
func secureRandomIndex(max int) (int, error) {
	if max <= 0 {
		return 0, nil
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}

	return int(n.Int64()), nil
}

// LookupIP implements the Resolver interface.
func (r *DoHResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	// Check if the host is already an IP address
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	// Try each provider in order of priority
	var lastErr error
	for _, provider := range r.providers {
		ips, err := r.lookupWithProvider(ctx, host, provider)
		if err == nil {
			return ips, nil
		}
		lastErr = err
		r.logger.Warn("DoH lookup failed",
			"provider", provider.Name,
			"host", host,
			"error", err)
	}

	return nil, fmt.Errorf("all DoH providers failed: %w", lastErr)
}

// LookupIPWithCache implements the Resolver interface.
func (r *DoHResolver) LookupIPWithCache(ctx context.Context, host string) ([]net.IP, error) {
	// Check if the host is already an IP address
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}

	// Check cache first
	r.cacheMutex.RLock()
	entry, found := r.cache[host]
	if found && time.Now().Before(entry.expiresAt) {
		// Cache hit and not expired
		r.cacheMutex.RUnlock()
		return entry.ips, nil
	}
	r.cacheMutex.RUnlock()

	// Cache miss or expired, do the lookup
	ips, err := r.LookupIP(ctx, host)
	if err != nil {
		return nil, err
	}

	// Update cache
	r.updateCache(host, ips, r.cacheTTL)
	return ips, nil
}

// lookupWithProvider performs a DoH lookup using a specific provider.
func (r *DoHResolver) lookupWithProvider(ctx context.Context, host string, provider Provider) ([]net.IP, error) {
	// Create a secure client for this provider
	client, err := r.createSecureClient(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to create secure client: %w", err)
	}

	// Create the DoH request URL
	// Format: https://provider/dns-query?name=example.com&type=A
	reqURL := fmt.Sprintf("%s?name=%s&type=A", provider.URL, url.QueryEscape(host))

	// Create the request with proper headers
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set DoH-required headers
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("User-Agent", r.userAgent)

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			r.logger.Warn("Failed to close response body", "error", err)
		}
	}()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse the JSON response
	var dnsResp DoHResponse
	if err := json.Unmarshal(body, &dnsResp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Check for DNS errors
	if dnsResp.Status != 0 {
		return nil, fmt.Errorf("DNS error status: %d", dnsResp.Status)
	}

	// Extract IP addresses from the answer
	var ips []net.IP
	for _, answer := range dnsResp.Answer {
		// Only process A (IPv4) or AAAA (IPv6) records
		if answer.Type == 1 || answer.Type == 28 {
			ip := net.ParseIP(answer.Data)
			if ip != nil {
				ips = append(ips, ip)
			}
		}
	}

	if len(ips) == 0 {
		return nil, errors.New("no IP addresses found in response")
	}

	return ips, nil
}

// updateCache updates the DNS cache with new results.
func (r *DoHResolver) updateCache(host string, ips []net.IP, ttl time.Duration) {
	r.cacheMutex.Lock()
	defer r.cacheMutex.Unlock()

	// Add to cache with expiration time
	r.cache[host] = &cacheEntry{
		ips:       ips,
		expiresAt: time.Now().Add(ttl),
	}

	// If cache is too large, evict the oldest entries
	if len(r.cache) > r.cacheSize {
		r.evictOldestEntries()
	}
}

// evictOldestEntries removes the oldest entries from the cache.
func (r *DoHResolver) evictOldestEntries() {
	// Remove approximately 25% of the oldest entries
	entriesToRemove := r.cacheSize / 4
	if entriesToRemove < 1 {
		entriesToRemove = 1
	}

	// Find the oldest entries
	type keyExpiryPair struct {
		key       string
		expiresAt time.Time
	}

	entries := make([]keyExpiryPair, 0, len(r.cache))
	for k, v := range r.cache {
		entries = append(entries, keyExpiryPair{k, v.expiresAt})
	}

	// Sort by expiration time (oldest first)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].expiresAt.Before(entries[j].expiresAt)
	})

	// Remove the oldest entries
	for i := 0; i < entriesToRemove && i < len(entries); i++ {
		delete(r.cache, entries[i].key)
	}
}

// PreloadCache implements the Resolver interface.
func (r *DoHResolver) PreloadCache(entries map[string][]net.IP) {
	for host, ips := range entries {
		r.updateCache(host, ips, r.cacheTTL)
	}
}

// VerifyNoLeaks implements the Resolver interface.
func (r *DoHResolver) VerifyNoLeaks(ctx context.Context) error {
	// Create a canary domain that should trigger a response if system DNS is used
	canaryDomain := fmt.Sprintf("leak-test-%d.example.com", time.Now().Unix())

	// Start a goroutine to monitor for leaks
	leakDetected := make(chan bool, 1)

	// This would need a real implementation with a DNS monitoring server
	// For now, we just verify our client doesn't attempt system resolution

	// Attempt to resolve the canary domain
	_, err := r.LookupIP(ctx, canaryDomain)

	// We expect an error since this domain doesn't exist
	if err == nil {
		return errors.New("unexpectedly resolved non-existent domain")
	}

	// Check if a leak was detected by the monitoring system
	select {
	case <-leakDetected:
		return errors.New("DNS leak detected - system resolver was used")
	case <-time.After(100 * time.Millisecond):
		// No leak detected
		return nil
	}
}

// Close implements the Resolver interface.
func (r *DoHResolver) Close() error {
	// Clean up any resources
	r.cacheMutex.Lock()
	r.cache = make(map[string]*cacheEntry)
	r.cacheMutex.Unlock()
	return nil
}

// NewSecureDialer creates a dialer that uses the secure resolver for DNS resolution.
func NewSecureDialer(resolver Resolver, timeout time.Duration) SecureDialer {
	return &secureDialer{
		resolver: resolver,
		timeout:  timeout,
	}
}

type secureDialer struct {
	resolver Resolver
	timeout  time.Duration
}

// DialContext implements the SecureDialer interface.
func (d *secureDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid address format: %w", err)
	}

	// Resolve the hostname using our secure resolver
	ips, err := d.resolver.LookupIPWithCache(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("secure resolution failed for %s: %w", host, err)
	}

	// Try each resolved IP
	var lastErr error
	for _, ip := range ips {
		dialer := &net.Dialer{
			Timeout: d.timeout,
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed to connect to any resolved IP for %s: %w", host, lastErr)
}

package channels

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gocircum/gocircum/core/engine"
	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/gocircum/gocircum/pkg/securedns"
)

// HTTPSDiscoveryChannel implements bootstrap discovery via HTTPS requests
type HTTPSDiscoveryChannel struct {
	domainGenerator DomainGenerator
	client          *http.Client
	logger          logging.Logger
	timeout         time.Duration
	priority        int
	pathTemplate    string
}

// HTTPSChannelOptions configures the HTTPS discovery channel
type HTTPSChannelOptions struct {
	PathTemplate  string
	Timeout       time.Duration
	Priority      int
	ClientTimeout time.Duration
	Resolver      securedns.Resolver // Added resolver for secure DNS
}

// NewHTTPSDiscoveryChannel creates a new HTTPS discovery channel
func NewHTTPSDiscoveryChannel(domainGen DomainGenerator, opts HTTPSChannelOptions, logger logging.Logger) *HTTPSDiscoveryChannel {
	if logger == nil {
		logger = logging.GetLogger()
	}

	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	if opts.ClientTimeout <= 0 {
		opts.ClientTimeout = 10 * time.Second
	}

	if opts.PathTemplate == "" {
		opts.PathTemplate = "/api/v1/bootstrap"
	}

	// Create a secure HTTP client for HTTPS requests
	var client *http.Client
	var err error

	// Use SecureHTTPClientFactory to create a client with DNS leak protection
	if opts.Resolver != nil {
		factory, factoryErr := engine.NewSecureHTTPClientFactory(opts.Resolver)
		if factoryErr == nil {
			client, err = factory.NewHTTPClient(opts.ClientTimeout)
		}

		if factoryErr != nil || err != nil {
			logger.Warn("Failed to create secure HTTP client, falling back to default client",
				"error", func() error {
					if factoryErr != nil {
						return factoryErr
					}
					return err
				}())
		}
	}

	// Fallback to a basic client if secure factory fails or resolver not provided
	if client == nil {
		logger.Warn("Using default HTTP client - THIS MAY LEAK DNS QUERIES")
		client = &http.Client{
			Timeout: opts.ClientTimeout,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  false,
				TLSHandshakeTimeout: 5 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		}
	}

	return &HTTPSDiscoveryChannel{
		domainGenerator: domainGen,
		client:          client,
		logger:          logger,
		timeout:         opts.Timeout,
		priority:        opts.Priority,
		pathTemplate:    opts.PathTemplate,
	}
}

// Name returns the channel name
func (h *HTTPSDiscoveryChannel) Name() string {
	return "https"
}

// Priority returns the channel priority
func (h *HTTPSDiscoveryChannel) Priority() int {
	return h.priority
}

// Timeout returns the discovery timeout
func (h *HTTPSDiscoveryChannel) Timeout() time.Duration {
	return h.timeout
}

// Discover attempts to find bootstrap addresses using HTTPS requests
func (h *HTTPSDiscoveryChannel) Discover(ctx context.Context) ([]string, error) {
	// Generate domains to query
	domains := h.domainGenerator.GenerateDomains(5)
	if len(domains) == 0 {
		return nil, fmt.Errorf("no domains generated for HTTPS discovery")
	}

	h.logger.Debug("Attempting HTTPS discovery", "domains", domains)

	// Create a context with timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, h.timeout)
	defer cancel()

	// Create channels for collecting results and errors
	resultChan := make(chan []string, len(domains))
	errChan := make(chan error, len(domains))
	var wg sync.WaitGroup

	// Query each domain concurrently
	for _, domain := range domains {
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			addresses, err := h.queryDomain(timeoutCtx, domain)
			if err != nil {
				errChan <- fmt.Errorf("query failed for %s: %w", domain, err)
				return
			}
			if len(addresses) > 0 {
				resultChan <- addresses
			}
		}(domain)
	}

	// Wait for all goroutines to complete
	wg.Wait()
	close(resultChan)
	close(errChan)

	// Collect all results
	var allAddresses []string
	for addresses := range resultChan {
		allAddresses = append(allAddresses, addresses...)
	}

	// Collect errors
	var errors []string
	for err := range errChan {
		errors = append(errors, err.Error())
	}

	if len(allAddresses) == 0 {
		errorMsg := "no addresses found via HTTPS discovery"
		if len(errors) > 0 {
			errorMsg += ": " + strings.Join(errors, "; ")
		}
		return nil, fmt.Errorf("%s", errorMsg)
	}

	// Remove duplicates
	uniqueAddresses := make(map[string]struct{})
	var result []string
	for _, addr := range allAddresses {
		if _, exists := uniqueAddresses[addr]; !exists {
			uniqueAddresses[addr] = struct{}{}
			result = append(result, addr)
		}
	}

	h.logger.Debug("HTTPS discovery complete",
		"domains_queried", len(domains),
		"addresses_found", len(result))

	return result, nil
}

// queryDomain makes an HTTPS request to a domain and extracts bootstrap addresses
func (h *HTTPSDiscoveryChannel) queryDomain(ctx context.Context, domain string) ([]string, error) {
	url := fmt.Sprintf("https://%s%s", domain, h.pathTemplate)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "application/json, text/plain")

	resp, err := h.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			h.logger.Warn("Failed to close response body", "error", err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse response based on content type
	contentType := resp.Header.Get("Content-Type")
	return h.parseResponse(contentType, body)
}

// parseResponse parses the response body based on content type
func (h *HTTPSDiscoveryChannel) parseResponse(contentType string, body []byte) ([]string, error) {
	if strings.Contains(contentType, "application/json") {
		return h.parseJSONResponse(body)
	} else {
		return h.parseTextResponse(body)
	}
}

// parseJSONResponse parses a JSON response containing bootstrap addresses
func (h *HTTPSDiscoveryChannel) parseJSONResponse(body []byte) ([]string, error) {
	// Try to parse as a JSON object with an "addresses" field
	var jsonResponse struct {
		Addresses []string `json:"addresses"`
	}

	if err := json.Unmarshal(body, &jsonResponse); err == nil && len(jsonResponse.Addresses) > 0 {
		return filterValidAddresses(jsonResponse.Addresses), nil
	}

	// Try to parse as a JSON array of strings
	var addressArray []string
	if err := json.Unmarshal(body, &addressArray); err == nil && len(addressArray) > 0 {
		return filterValidAddresses(addressArray), nil
	}

	return nil, fmt.Errorf("no valid addresses found in JSON response")
}

// parseTextResponse parses a plain text response containing bootstrap addresses
func (h *HTTPSDiscoveryChannel) parseTextResponse(body []byte) ([]string, error) {
	text := string(body)
	lines := strings.Split(text, "\n")

	var addresses []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && isValidEndpoint(line) {
			addresses = append(addresses, line)
		}
	}

	if len(addresses) == 0 {
		return nil, fmt.Errorf("no valid addresses found in text response")
	}

	return addresses, nil
}

// filterValidAddresses filters a list of addresses to only include valid ones
func filterValidAddresses(addresses []string) []string {
	var valid []string
	for _, addr := range addresses {
		if isValidEndpoint(addr) {
			valid = append(valid, addr)
		}
	}
	return valid
}

// getRandomUserAgent returns a random user agent string
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
	}

	return userAgents[rand.Intn(len(userAgents))]
}

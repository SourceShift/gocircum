package channels

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gocircum/gocircum/core/engine"
	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/gocircum/gocircum/pkg/securedns"
)

// PeerExchangeChannel implements discovery via peer-to-peer communications
type PeerExchangeChannel struct {
	peerCache      map[string]PeerInfo
	mutex          sync.RWMutex
	client         *http.Client
	logger         logging.Logger
	timeout        time.Duration
	priority       int
	refreshTimeout time.Duration
	lastRefresh    time.Time
}

// PeerInfo holds information about a peer node
type PeerInfo struct {
	Address      string    `json:"address"`
	LastSeen     time.Time `json:"last_seen"`
	SuccessCount int       `json:"success_count"`
	FailCount    int       `json:"fail_count"`
	Reliability  float64   `json:"reliability"`
}

// PeerResponse represents the response from a peer exchange request
type PeerResponse struct {
	Addresses []string            `json:"addresses"`
	Peers     map[string]PeerInfo `json:"peers,omitempty"`
	Timestamp int64               `json:"timestamp"`
	TTL       int                 `json:"ttl"`
}

// PeerExchangeOptions configures the peer exchange channel
type PeerExchangeOptions struct {
	InitialPeers    []string
	Timeout         time.Duration
	Priority        int
	RefreshInterval time.Duration
	MaxPeers        int
	Resolver        securedns.Resolver // Added resolver for secure DNS
}

// NewPeerExchangeChannel creates a new peer exchange discovery channel
func NewPeerExchangeChannel(opts PeerExchangeOptions, logger logging.Logger) *PeerExchangeChannel {
	if logger == nil {
		logger = logging.GetLogger()
	}

	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = 30 * time.Minute
	}

	// Create a secure HTTP client for peer communication
	var client *http.Client
	var err error

	// Use SecureHTTPClientFactory to create a client with DNS leak protection
	if opts.Resolver != nil {
		factory, factoryErr := engine.NewSecureHTTPClientFactory(opts.Resolver)
		if factoryErr == nil {
			client, err = factory.NewHTTPClient(10 * time.Second)
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
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        20,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  false,
				TLSHandshakeTimeout: 5 * time.Second,
				ForceAttemptHTTP2:   true,
			},
		}
	}

	channel := &PeerExchangeChannel{
		peerCache:      make(map[string]PeerInfo),
		client:         client,
		logger:         logger,
		timeout:        opts.Timeout,
		priority:       opts.Priority,
		refreshTimeout: opts.RefreshInterval,
	}

	// Initialize peer cache with initial peers
	for _, peer := range opts.InitialPeers {
		if isValidEndpoint(peer) {
			channel.peerCache[peer] = PeerInfo{
				Address:      peer,
				LastSeen:     time.Now(),
				SuccessCount: 0,
				FailCount:    0,
				Reliability:  0.5, // Initial neutral reliability
			}
		}
	}

	return channel
}

// Name returns the channel name
func (p *PeerExchangeChannel) Name() string {
	return "peer_exchange"
}

// Priority returns the channel priority
func (p *PeerExchangeChannel) Priority() int {
	return p.priority
}

// Timeout returns the discovery timeout
func (p *PeerExchangeChannel) Timeout() time.Duration {
	return p.timeout
}

// Discover attempts to find bootstrap addresses using peer exchange
func (p *PeerExchangeChannel) Discover(ctx context.Context) ([]string, error) {
	// Check if we need to refresh our peer list first
	if time.Since(p.lastRefresh) > p.refreshTimeout {
		if err := p.refreshPeerList(ctx); err != nil {
			p.logger.Warn("Failed to refresh peer list", "error", err)
			// Continue with the existing peer list
		}
	}

	// Get a list of peers to query
	peers := p.getQueryablePeers(10)
	if len(peers) == 0 {
		return nil, fmt.Errorf("no peers available for discovery")
	}

	// Create a channel to collect addresses from each peer
	resultChan := make(chan []string, len(peers))
	errChan := make(chan error, len(peers))

	// Query each peer concurrently
	for _, peer := range peers {
		go func(peerAddr string) {
			addresses, err := p.queryPeer(ctx, peerAddr)
			if err != nil {
				p.updatePeerReliability(peerAddr, false)
				errChan <- err
				return
			}
			p.updatePeerReliability(peerAddr, true)
			resultChan <- addresses
		}(peer.Address)
	}

	// Collect results
	var allAddresses []string
	var errors []string

	// Wait for all queries to complete or timeout
	for i := 0; i < len(peers); i++ {
		select {
		case <-ctx.Done():
			return allAddresses, ctx.Err()
		case addresses := <-resultChan:
			allAddresses = append(allAddresses, addresses...)
		case err := <-errChan:
			errors = append(errors, err.Error())
		}
	}

	if len(allAddresses) == 0 {
		errorMsg := "no addresses found via peer exchange"
		if len(errors) > 0 {
			errorMsg += ": " + strings.Join(errors, "; ")
		}
		return nil, fmt.Errorf("%s", errorMsg)
	}

	// Filter out duplicates
	uniqueAddresses := make(map[string]struct{})
	var finalAddresses []string

	for _, addr := range allAddresses {
		if _, exists := uniqueAddresses[addr]; !exists {
			uniqueAddresses[addr] = struct{}{}
			finalAddresses = append(finalAddresses, addr)
		}
	}

	p.logger.Debug("Discovered addresses via peer exchange",
		"peer_count", len(peers),
		"address_count", len(finalAddresses))

	return finalAddresses, nil
}

// queryPeer queries a specific peer for bootstrap addresses
func (p *PeerExchangeChannel) queryPeer(ctx context.Context, peerAddr string) ([]string, error) {
	url := fmt.Sprintf("https://%s/api/v1/bootstrap/peers", peerAddr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Warn("Failed to close response body", "error", err)
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

	// Parse response
	var peerResponse PeerResponse
	if err := json.Unmarshal(body, &peerResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Store new peers in the cache
	if len(peerResponse.Peers) > 0 {
		p.mutex.Lock()
		for addr, info := range peerResponse.Peers {
			if isValidEndpoint(addr) {
				// Check if we already have this peer
				if existing, exists := p.peerCache[addr]; exists {
					// Update reliability score with a weighted average
					info.Reliability = (existing.Reliability*0.7 + info.Reliability*0.3)
					info.SuccessCount += existing.SuccessCount
					info.FailCount += existing.FailCount
				}
				p.peerCache[addr] = info
			}
		}
		p.mutex.Unlock()
	}

	// Filter addresses
	var validAddresses []string
	for _, addr := range peerResponse.Addresses {
		if isValidEndpoint(addr) {
			validAddresses = append(validAddresses, addr)
		}
	}

	return validAddresses, nil
}

// refreshPeerList updates the peer list by querying existing peers
func (p *PeerExchangeChannel) refreshPeerList(ctx context.Context) error {
	p.mutex.RLock()
	peerCount := len(p.peerCache)
	p.mutex.RUnlock()

	if peerCount == 0 {
		return fmt.Errorf("no peers in cache to refresh from")
	}

	// Select a subset of reliable peers to query
	peers := p.getQueryablePeers(5)
	if len(peers) == 0 {
		return fmt.Errorf("no reliable peers available for refresh")
	}

	// Query each peer for their peer list
	var newPeers int
	for _, peer := range peers {
		newPeersList, err := p.getPeerListFromPeer(ctx, peer.Address)
		if err != nil {
			p.logger.Warn("Failed to get peer list",
				"peer", peer.Address,
				"error", err)
			p.updatePeerReliability(peer.Address, false)
			continue
		}

		p.updatePeerReliability(peer.Address, true)

		// Add new peers to our cache
		p.mutex.Lock()
		for addr, info := range newPeersList {
			if isValidEndpoint(addr) {
				if _, exists := p.peerCache[addr]; !exists {
					p.peerCache[addr] = info
					newPeers++
				}
			}
		}
		p.mutex.Unlock()
	}

	p.lastRefresh = time.Now()

	p.logger.Debug("Refreshed peer list",
		"queried_peers", len(peers),
		"new_peers", newPeers,
		"total_peers", peerCount+newPeers)

	return nil
}

// getPeerListFromPeer queries a peer for its known peers
func (p *PeerExchangeChannel) getPeerListFromPeer(ctx context.Context, peerAddr string) (map[string]PeerInfo, error) {
	url := fmt.Sprintf("https://%s/api/v1/bootstrap/peer-list", peerAddr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", getRandomUserAgent())
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			p.logger.Warn("Failed to close response body", "error", err)
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

	// Parse response
	var peerList map[string]PeerInfo
	if err := json.Unmarshal(body, &peerList); err != nil {
		return nil, fmt.Errorf("failed to parse peer list: %w", err)
	}

	return peerList, nil
}

// getQueryablePeers returns a slice of peers to query, sorted by reliability
func (p *PeerExchangeChannel) getQueryablePeers(maxCount int) []PeerInfo {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	// Convert map to slice for sorting
	var peers []PeerInfo
	for _, info := range p.peerCache {
		// Only include peers seen in the last 24 hours
		if time.Since(info.LastSeen) < 24*time.Hour {
			peers = append(peers, info)
		}
	}

	// Sort by reliability (highest first)
	for i := 1; i < len(peers); i++ {
		j := i
		for j > 0 && peers[j-1].Reliability < peers[j].Reliability {
			peers[j], peers[j-1] = peers[j-1], peers[j]
			j--
		}
	}

	// Return at most maxCount peers
	if len(peers) > maxCount {
		peers = peers[:maxCount]
	}

	return peers
}

// updatePeerReliability updates the reliability score for a peer
func (p *PeerExchangeChannel) updatePeerReliability(peerAddr string, success bool) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	info, exists := p.peerCache[peerAddr]
	if !exists {
		return
	}

	// Update last seen
	info.LastSeen = time.Now()

	// Update success/fail counts
	if success {
		info.SuccessCount++
	} else {
		info.FailCount++
	}

	// Calculate reliability as success rate with some dampening
	totalAttempts := info.SuccessCount + info.FailCount
	if totalAttempts > 0 {
		successRate := float64(info.SuccessCount) / float64(totalAttempts)

		// Apply dampening to avoid extreme values based on few attempts
		dampeningFactor := min(1.0, float64(totalAttempts)/10.0)

		// Weighted average between current reliability and new success rate
		info.Reliability = info.Reliability*0.7 + (successRate*dampeningFactor)*0.3
	}

	p.peerCache[peerAddr] = info
}

// min returns the minimum of two float64 values
func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

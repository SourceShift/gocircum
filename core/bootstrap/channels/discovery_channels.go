package channels

import (
	"context"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/gocircum/gocircum/pkg/securerandom"
)

// DiscoveryChannel represents a mechanism for discovering bootstrap endpoints
type DiscoveryChannel interface {
	// Name returns the identifier for this discovery channel
	Name() string

	// Discover attempts to find bootstrap endpoints using this channel
	Discover(ctx context.Context) ([]string, error)

	// Priority returns the priority of this channel (higher values tried first)
	Priority() int

	// Timeout returns the timeout for discovery operations
	Timeout() time.Duration
}

// ChannelResult represents the result of a discovery attempt
type ChannelResult struct {
	ChannelName string
	Addresses   []string
	Error       error
	Quality     float64
}

// DiscoveryManager orchestrates multiple discovery channels
type DiscoveryManager struct {
	channels        []DiscoveryChannel
	logger          logging.Logger
	results         map[string]ChannelResult
	mutex           sync.RWMutex
	minChannelCount int
}

// NewDiscoveryManager creates a new discovery manager
func NewDiscoveryManager(logger logging.Logger, minChannelCount int) *DiscoveryManager {
	if logger == nil {
		logger = logging.GetLogger()
	}

	return &DiscoveryManager{
		channels:        make([]DiscoveryChannel, 0),
		logger:          logger,
		results:         make(map[string]ChannelResult),
		minChannelCount: minChannelCount,
	}
}

// RegisterChannel adds a discovery channel to the manager
func (m *DiscoveryManager) RegisterChannel(channel DiscoveryChannel) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.channels = append(m.channels, channel)

	// Sort channels by priority (highest first)
	m.sortChannelsByPriority()
}

// sortChannelsByPriority sorts the channels by priority (highest first)
func (m *DiscoveryManager) sortChannelsByPriority() {
	// Simple insertion sort for small slices
	for i := 1; i < len(m.channels); i++ {
		j := i
		for j > 0 && m.channels[j-1].Priority() < m.channels[j].Priority() {
			m.channels[j], m.channels[j-1] = m.channels[j-1], m.channels[j]
			j--
		}
	}
}

// DiscoverEndpoints attempts to discover endpoints using all registered channels
func (m *DiscoveryManager) DiscoverEndpoints(ctx context.Context) ([]string, error) {
	m.mutex.RLock()
	channelCount := len(m.channels)
	m.mutex.RUnlock()

	if channelCount == 0 {
		return nil, fmt.Errorf("no discovery channels registered")
	}

	// Create a channel to collect results
	results := make(chan ChannelResult, channelCount)

	// Create a context with timeout
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	// Launch discovery for each channel
	var wg sync.WaitGroup
	m.mutex.RLock()
	for _, channel := range m.channels {
		wg.Add(1)
		go func(ch DiscoveryChannel) {
			defer wg.Done()

			// Create a context with the channel's timeout
			chCtx, chCancel := context.WithTimeout(ctx, ch.Timeout())
			defer chCancel()

			m.logger.Debug("Starting discovery with channel",
				"channel", ch.Name(),
				"timeout", ch.Timeout().String())

			start := time.Now()
			addresses, err := ch.Discover(chCtx)
			elapsed := time.Since(start)

			result := ChannelResult{
				ChannelName: ch.Name(),
				Addresses:   addresses,
				Error:       err,
				Quality:     calculateChannelQuality(addresses, err, elapsed),
			}

			// Store the result
			m.mutex.Lock()
			m.results[ch.Name()] = result
			m.mutex.Unlock()

			// Send to the results channel
			select {
			case results <- result:
			case <-ctx.Done():
			}
		}(channel)
	}
	m.mutex.RUnlock()

	// Wait for all discoveries to complete or context to be canceled
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and process results
	var allAddresses []string
	var successCount int
	channelMap := make(map[string][]string)

	for result := range results {
		if result.Error != nil {
			m.logger.Warn("Channel discovery failed",
				"channel", result.ChannelName,
				"error", result.Error)
			continue
		}

		if len(result.Addresses) > 0 {
			m.logger.Debug("Discovery successful",
				"channel", result.ChannelName,
				"address_count", len(result.Addresses),
				"quality", result.Quality)

			channelMap[result.ChannelName] = result.Addresses
			allAddresses = append(allAddresses, result.Addresses...)
			successCount++
		}
	}

	// Check if we have enough successful channels
	if successCount < m.minChannelCount {
		m.logger.Warn("Insufficient successful discovery channels",
			"successful", successCount,
			"required", m.minChannelCount)

		// If we have some addresses, return them with a warning
		if len(allAddresses) > 0 {
			m.logger.Warn("Using addresses despite insufficient channel diversity",
				"address_count", len(allAddresses))
			return allAddresses, nil
		}

		return nil, fmt.Errorf("insufficient successful discovery channels: %d/%d",
			successCount, m.minChannelCount)
	}

	// Apply consensus filtering to remove outliers and verify endpoints
	consensusAddresses := m.applyConsensusFiltering(channelMap)

	if len(consensusAddresses) > 0 {
		m.logger.Info("Endpoint discovery successful",
			"address_count", len(consensusAddresses),
			"successful_channels", successCount)
		return consensusAddresses, nil
	}

	return allAddresses, nil
}

// applyConsensusFiltering filters addresses based on cross-channel consensus
func (m *DiscoveryManager) applyConsensusFiltering(channelMap map[string][]string) []string {
	// Count occurrences of each address across channels
	addressCounts := make(map[string]int)
	for _, addresses := range channelMap {
		// Track unique addresses within this channel to avoid double-counting
		seen := make(map[string]bool)

		for _, addr := range addresses {
			if !seen[addr] {
				addressCounts[addr]++
				seen[addr] = true
			}
		}
	}

	// Apply threshold filtering (addresses must appear in multiple channels)
	var consensusAddresses []string
	channelCount := len(channelMap)
	threshold := 1 // Minimum required channels for consensus

	if channelCount >= 3 {
		threshold = 2 // At least 2 channels must agree
	}

	for addr, count := range addressCounts {
		if count >= threshold {
			consensusAddresses = append(consensusAddresses, addr)
		}
	}

	// Randomly shuffle the consensus addresses
	return secureShuffleAddresses(consensusAddresses)
}

// secureShuffleAddresses randomizes the order of addresses using secure random
func secureShuffleAddresses(addresses []string) []string {
	result := make([]string, len(addresses))
	copy(result, addresses)

	for i := len(result) - 1; i > 0; i-- {
		j, err := securerandom.Int(0, i)
		if err != nil {
			// Log and continue with current order if randomization fails
			logging.GetLogger().Warn("Failed to generate secure random number for shuffling",
				"error", err)
			return result
		}

		result[i], result[j] = result[j], result[i]
	}

	return result
}

// calculateChannelQuality returns a quality score based on result and timing
func calculateChannelQuality(addresses []string, err error, elapsed time.Duration) float64 {
	if err != nil {
		return 0.0
	}

	addressCount := len(addresses)
	if addressCount == 0 {
		return 0.0
	}

	// Base quality based on number of addresses (0.1-0.5)
	quality := 0.1 + math.Min(0.4, float64(addressCount)*0.05)

	// Adjust for response time (0-0.5)
	// Faster responses get higher quality, with diminishing returns
	timeQuality := 0.5 * math.Max(0, 1-elapsed.Seconds()/10)

	return quality + timeQuality
}

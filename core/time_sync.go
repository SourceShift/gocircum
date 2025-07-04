package core

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
)

const (
	// DefaultNTPPort is the standard port for NTP servers
	DefaultNTPPort = 123

	// DefaultNTPTimeout is the default timeout for NTP requests
	DefaultNTPTimeout = 5 * time.Second

	// DefaultTimeCachePath is the default location for the time cache file
	DefaultTimeCachePath = "time_cache.json"

	// DefaultRefreshInterval is how often to refresh the time from NTP by default
	DefaultRefreshInterval = 1 * time.Hour

	// DefaultMaxTimeDeviation is the maximum allowed deviation between system time and NTP time
	DefaultMaxTimeDeviation = 2 * time.Second

	// DefaultLookbackWindows is the number of past time windows to consider for domain generation
	DefaultLookbackWindows = 2

	// DefaultLookaheadWindows is the number of future time windows to consider for domain generation
	DefaultLookaheadWindows = 2
)

// TimeSyncConfig holds configuration for the time synchronization service
type TimeSyncConfig struct {
	// NTPServers is a list of NTP server hostnames or IPs to query
	NTPServers []string

	// RefreshInterval is how often to refresh the time from NTP
	RefreshInterval time.Duration

	// MaxTimeDeviation is the maximum allowed deviation between system time and NTP time
	MaxTimeDeviation time.Duration

	// TimeCachePath is the file path for caching time information
	TimeCachePath string

	// LookbackWindows is the number of past time windows to consider for domain generation
	LookbackWindows int

	// LookaheadWindows is the number of future time windows to consider for domain generation
	LookaheadWindows int

	// QuantizationWindow is the time window size for quantization
	QuantizationWindow time.Duration
}

// NewTimeSyncConfig creates a default time sync configuration
func NewTimeSyncConfig() *TimeSyncConfig {
	return &TimeSyncConfig{
		NTPServers: []string{
			"time.google.com",
			"pool.ntp.org",
			"time.cloudflare.com",
			"time.apple.com",
		},
		RefreshInterval:    DefaultRefreshInterval,
		MaxTimeDeviation:   DefaultMaxTimeDeviation,
		TimeCachePath:      DefaultTimeCachePath,
		LookbackWindows:    DefaultLookbackWindows,
		LookaheadWindows:   DefaultLookaheadWindows,
		QuantizationWindow: 1 * time.Hour,
	}
}

// TimeCache is used for storing time offset information to disk
type TimeCache struct {
	// LastNTPTime is the last successfully retrieved NTP time
	LastNTPTime time.Time `json:"last_ntp_time"`

	// SystemTimeAtRetrieval is the system time when NTP time was retrieved
	SystemTimeAtRetrieval time.Time `json:"system_time_at_retrieval"`

	// Offset is the calculated offset between system time and NTP time
	Offset time.Duration `json:"offset"`

	// LastUpdate is when the cache was last updated
	LastUpdate time.Time `json:"last_update"`
}

// TimeSynchronizer provides accurate time for deterministic domain generation
type TimeSynchronizer struct {
	config     *TimeSyncConfig
	logger     logging.Logger
	mutex      sync.RWMutex
	timeCache  *TimeCache
	quantizer  *TimeQuantizer
	lastDrift  time.Duration
	driftCount int
}

// NewTimeSynchronizer creates a new time synchronization service
func NewTimeSynchronizer(cfg *TimeSyncConfig, logger logging.Logger) (*TimeSynchronizer, error) {
	if cfg == nil {
		cfg = NewTimeSyncConfig()
	}

	if logger == nil {
		logger = logging.GetLogger()
	}

	quantizer := NewTimeQuantizer(cfg.QuantizationWindow)

	ts := &TimeSynchronizer{
		config:    cfg,
		logger:    logger.With("component", "timesync"),
		quantizer: quantizer,
	}

	// Try to load cached time information
	err := ts.loadTimeCache()
	if err != nil {
		ts.logger.Info("Could not load time cache, will create new one", "error", err)
		// Not a fatal error, will create a new cache
	}

	// Initialize cache if not loaded
	if ts.timeCache == nil {
		ts.timeCache = &TimeCache{
			LastUpdate: time.Now(),
		}
	}

	// Perform initial time sync
	if err := ts.syncTime(); err != nil {
		ts.logger.Warn("Initial time sync failed, using system time", "error", err)
		// Not fatal, will use system time and retry later
	}

	// Start background refresh goroutine
	go ts.refreshLoop()

	return ts, nil
}

// GetCurrentTime returns the current time adjusted for NTP offset if available
func (ts *TimeSynchronizer) GetCurrentTime() time.Time {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()

	if ts.timeCache == nil || ts.timeCache.LastUpdate.IsZero() {
		// No cached time, use system time
		return time.Now()
	}

	// Calculate time based on saved offset
	return time.Now().Add(ts.timeCache.Offset)
}

// GetQuantizedTime returns the current time quantized to the configured window
func (ts *TimeSynchronizer) GetQuantizedTime() time.Time {
	currentTime := ts.GetCurrentTime()
	return ts.quantizer.Quantize(currentTime)
}

// GetTimeWindows returns time windows for domain generation, including past and future windows
func (ts *TimeSynchronizer) GetTimeWindows() []time.Time {
	current := ts.GetQuantizedTime()
	windows := make([]time.Time, 0, 1+ts.config.LookbackWindows+ts.config.LookaheadWindows)

	// Add past windows
	for i := ts.config.LookbackWindows; i > 0; i-- {
		pastWindow := current.Add(-time.Duration(i) * ts.quantizer.window)
		windows = append(windows, pastWindow)
	}

	// Add current window
	windows = append(windows, current)

	// Add future windows
	for i := 1; i <= ts.config.LookaheadWindows; i++ {
		futureWindow := current.Add(time.Duration(i) * ts.quantizer.window)
		windows = append(windows, futureWindow)
	}

	return windows
}

// IsTimeAccurate returns true if we have a recent NTP sync
func (ts *TimeSynchronizer) IsTimeAccurate() bool {
	ts.mutex.RLock()
	defer ts.mutex.RUnlock()

	if ts.timeCache == nil || ts.timeCache.LastUpdate.IsZero() {
		return false
	}

	// Check if last update was within refresh interval
	stale := time.Since(ts.timeCache.LastUpdate) > ts.config.RefreshInterval
	return !stale
}

// refreshLoop periodically refreshes the time from NTP servers
func (ts *TimeSynchronizer) refreshLoop() {
	// Add some jitter to prevent thundering herd
	jitter := time.Duration(rand.Int63n(int64(30 * time.Second)))
	time.Sleep(jitter)

	ticker := time.NewTicker(ts.config.RefreshInterval)
	defer ticker.Stop()

	for {
		<-ticker.C
		if err := ts.syncTime(); err != nil {
			ts.logger.Warn("Failed to sync time", "error", err)
		}
	}
}

// syncTime queries NTP servers and updates the time offset
func (ts *TimeSynchronizer) syncTime() error {
	ts.mutex.Lock()
	defer ts.mutex.Unlock()

	var lastErr error
	for _, server := range ts.config.NTPServers {
		ntpTime, err := ts.queryNTPServer(server)
		if err != nil {
			lastErr = err
			ts.logger.Debug("Failed to query NTP server", "server", server, "error", err)
			continue
		}

		// Successfully retrieved time
		systemTime := time.Now()
		offset := ntpTime.Sub(systemTime)

		// Check for significant drift
		if ts.timeCache != nil && !ts.timeCache.LastUpdate.IsZero() {
			drift := offset - ts.timeCache.Offset
			if drift < 0 {
				drift = -drift
			}

			// Log significant drift for monitoring
			if drift > ts.config.MaxTimeDeviation {
				ts.lastDrift = drift
				ts.driftCount++
				ts.logger.Warn("Significant time drift detected",
					"drift", drift.String(),
					"count", ts.driftCount)
			}
		}

		// Update time cache
		ts.timeCache = &TimeCache{
			LastNTPTime:           ntpTime,
			SystemTimeAtRetrieval: systemTime,
			Offset:                offset,
			LastUpdate:            systemTime,
		}

		// Save to disk
		if err := ts.saveTimeCache(); err != nil {
			ts.logger.Warn("Failed to save time cache", "error", err)
		}

		ts.logger.Debug("Time synchronized successfully",
			"server", server,
			"offset", offset.String())

		return nil
	}

	return fmt.Errorf("all NTP servers failed: %v", lastErr)
}

// queryNTPServer gets time from an NTP server using a simplified NTP client implementation
func (ts *TimeSynchronizer) queryNTPServer(server string) (time.Time, error) {
	// Add default port if not specified
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, fmt.Sprintf("%d", DefaultNTPPort))
	}

	// Connect to NTP server
	conn, err := net.DialTimeout("udp", server, DefaultNTPTimeout)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to connect to NTP server: %v", err)
	}
	defer func() {
		err := conn.Close()
		if err != nil {
			ts.logger.Debug("Error closing NTP connection", "error", err)
		}
	}()

	// Set read deadline
	if err := conn.SetReadDeadline(time.Now().Add(DefaultNTPTimeout)); err != nil {
		return time.Time{}, fmt.Errorf("failed to set read deadline: %v", err)
	}

	// Create NTP request packet (48 bytes per spec)
	// This is a simplified NTP client implementation
	// For production use, consider using a full NTP client library
	req := make([]byte, 48)
	// Set LI (leap indicator), VN (version number), and Mode
	// Mode 3 is client request to server
	req[0] = 0x1B // (No leap warning, version 3, mode 3)

	// Send request
	if _, err := conn.Write(req); err != nil {
		return time.Time{}, fmt.Errorf("failed to send NTP request: %v", err)
	}

	// Read response
	resp := make([]byte, 48)
	if _, err := conn.Read(resp); err != nil {
		return time.Time{}, fmt.Errorf("failed to read NTP response: %v", err)
	}

	// Check server response
	mode := resp[0] & 0x7
	if mode != 4 {
		return time.Time{}, fmt.Errorf("invalid NTP response mode: %d", mode)
	}

	// Extract transmit timestamp (seconds and fraction since Jan 1, 1900)
	// NTP timestamps are represented as a 64-bit value
	// First 32 bits are seconds, next 32 bits are fraction of second
	// The transmit timestamp is at offset 40 in the response
	secSince1900 := uint64(resp[40])<<24 | uint64(resp[41])<<16 | uint64(resp[42])<<8 | uint64(resp[43])
	fracSec := uint64(resp[44])<<24 | uint64(resp[45])<<16 | uint64(resp[46])<<8 | uint64(resp[47])

	// Convert to time.Time
	// NTP epoch starts Jan 1, 1900, Unix epoch starts Jan 1, 1970
	// Difference is 70 years plus 17 leap days = 2208988800 seconds
	const ntpEpochOffset = 2208988800
	secs := int64(secSince1900 - ntpEpochOffset)
	nanos := int64(fracSec * uint64(time.Second) / 0x100000000)

	return time.Unix(secs, nanos).UTC(), nil
}

// loadTimeCache loads the time cache from disk
func (ts *TimeSynchronizer) loadTimeCache() error {
	data, err := os.ReadFile(ts.config.TimeCachePath)
	if err != nil {
		return err
	}

	cache := &TimeCache{}
	if err := json.Unmarshal(data, cache); err != nil {
		return err
	}

	ts.timeCache = cache
	return nil
}

// saveTimeCache saves the time cache to disk
func (ts *TimeSynchronizer) saveTimeCache() error {
	data, err := json.Marshal(ts.timeCache)
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(ts.config.TimeCachePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Write atomically using rename
	tempFile := ts.config.TimeCachePath + ".tmp"
	if err := os.WriteFile(tempFile, data, 0644); err != nil {
		return err
	}

	return os.Rename(tempFile, ts.config.TimeCachePath)
}

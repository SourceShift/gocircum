package securedns

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
)

// TimeSynchronizer provides accurate time for DGA operations
// It implements the TimeSynchronizerInterface
type TimeSynchronizer struct {
	ntpServers           []string
	quantizationInterval time.Duration
	maxDriftThreshold    time.Duration
	windowTolerance      time.Duration
	lastSyncTime         time.Time
	timeOffset           time.Duration
	cacheMutex           sync.RWMutex
	logger               logging.Logger
}

// TimeSyncConfig contains configuration for the time synchronizer
type TimeSyncConfig struct {
	// NTPServers is the list of NTP servers to use
	NTPServers []string
	// QuantizationInterval is how time should be quantized
	QuantizationInterval time.Duration
	// MaxDriftThreshold is the maximum allowed time drift
	MaxDriftThreshold time.Duration
	// WindowTolerance is the allowed tolerance window for time synchronization
	WindowTolerance time.Duration
}

// NewTimeSynchronizer creates a new time synchronizer
func NewTimeSynchronizer(config *TimeSyncConfig, logger logging.Logger) (*TimeSynchronizer, error) {
	if config == nil {
		config = &TimeSyncConfig{
			NTPServers:           []string{"pool.ntp.org", "time.google.com", "time.cloudflare.com"},
			QuantizationInterval: 1 * time.Hour,
			MaxDriftThreshold:    2 * time.Second,
			WindowTolerance:      30 * time.Second,
		}
	}

	if logger == nil {
		logger = logging.GetLogger()
	}

	logger = logger.With("component", "time-sync")

	return &TimeSynchronizer{
		ntpServers:           config.NTPServers,
		quantizationInterval: config.QuantizationInterval,
		maxDriftThreshold:    config.MaxDriftThreshold,
		windowTolerance:      config.WindowTolerance,
		lastSyncTime:         time.Time{},
		timeOffset:           0,
		logger:               logger,
	}, nil
}

// GetAccurateTime returns the current time, synchronized with NTP if possible
func (ts *TimeSynchronizer) GetAccurateTime() (time.Time, error) {
	// This is a simplified implementation
	// In a real implementation, this would use NTP to get an accurate time
	// and calculate the offset from the system clock

	ts.cacheMutex.RLock()
	offset := ts.timeOffset
	ts.cacheMutex.RUnlock()

	// Apply the offset to the current system time
	return time.Now().Add(offset), nil
}

// SyncTime synchronizes the local time with NTP servers
func (ts *TimeSynchronizer) SyncTime(ctx context.Context) error {
	// This is a simplified implementation
	// In a real implementation, this would:
	// 1. Query multiple NTP servers
	// 2. Calculate the offset between local time and NTP time
	// 3. Update the timeOffset value
	// 4. Check for drift and potentially log warnings

	// For now, we'll just pretend the time is synchronized
	ts.cacheMutex.Lock()
	defer ts.cacheMutex.Unlock()

	ts.lastSyncTime = time.Now()
	// In a real implementation, we would calculate a real offset
	ts.timeOffset = 0

	return nil
}

// QuantizeTime rounds a timestamp to the nearest quantization interval
func (ts *TimeSynchronizer) QuantizeTime(t time.Time) time.Time {
	unixTime := t.Unix()
	intervalSeconds := int64(ts.quantizationInterval.Seconds())
	quantized := unixTime - (unixTime % intervalSeconds)
	return time.Unix(quantized, 0).UTC()
}

// GetQuantizationInterval returns the current quantization interval
func (ts *TimeSynchronizer) GetQuantizationInterval() time.Duration {
	return ts.quantizationInterval
}

// GetTimeWindow returns a time window around the given time
func (ts *TimeSynchronizer) GetTimeWindow(t time.Time) (time.Time, time.Time) {
	// Calculate the window boundaries based on the tolerance
	return t.Add(-ts.windowTolerance), t.Add(ts.windowTolerance)
}

// GetCurrentAndAdjacentWindows returns the current time window and adjacent windows
func (ts *TimeSynchronizer) GetCurrentAndAdjacentWindows(count int) ([]time.Time, error) {
	if count <= 0 {
		return nil, fmt.Errorf("count must be positive")
	}

	currentTime, err := ts.GetAccurateTime()
	if err != nil {
		return nil, fmt.Errorf("failed to get accurate time: %w", err)
	}

	quantizedCurrent := ts.QuantizeTime(currentTime)
	windows := make([]time.Time, count)

	// Current window is always first
	windows[0] = quantizedCurrent

	// Add previous and future windows
	for i := 1; i < count; i++ {
		if i%2 == 1 {
			// Previous window
			offset := (i + 1) / 2
			windows[i] = quantizedCurrent.Add(-time.Duration(offset) * ts.quantizationInterval)
		} else {
			// Future window
			offset := i / 2
			windows[i] = quantizedCurrent.Add(time.Duration(offset) * ts.quantizationInterval)
		}
	}

	return windows, nil
}

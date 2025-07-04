package core

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTimeQuantizer(t *testing.T) {
	t.Run("basic_quantization", func(t *testing.T) {
		window := 1 * time.Hour
		quantizer := NewTimeQuantizer(window)

		input := time.Date(2023, 5, 15, 12, 30, 45, 0, time.UTC)
		expected := time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC)
		result := quantizer.Quantize(input)

		assert.Equal(t, expected, result)
	})

	t.Run("different_window_sizes", func(t *testing.T) {
		testCases := []struct {
			name     string
			window   time.Duration
			input    time.Time
			expected time.Time
		}{
			{
				name:     "1_hour",
				window:   1 * time.Hour,
				input:    time.Date(2023, 5, 15, 12, 30, 0, 0, time.UTC),
				expected: time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC),
			},
			{
				name:     "day",
				window:   24 * time.Hour,
				input:    time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC),
				expected: time.Date(2023, 5, 15, 0, 0, 0, 0, time.UTC),
			},
			{
				name:     "30_minutes",
				window:   30 * time.Minute,
				input:    time.Date(2023, 5, 15, 12, 45, 0, 0, time.UTC),
				expected: time.Date(2023, 5, 15, 12, 30, 0, 0, time.UTC),
			},
			{
				name:     "5_minutes",
				window:   5 * time.Minute,
				input:    time.Date(2023, 5, 15, 12, 17, 0, 0, time.UTC),
				expected: time.Date(2023, 5, 15, 12, 15, 0, 0, time.UTC),
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				quantizer := NewTimeQuantizer(tc.window)
				result := quantizer.Quantize(tc.input)
				assert.Equal(t, tc.expected, result)
			})
		}
	})

	t.Run("zero_window", func(t *testing.T) {
		// Should default to 1 hour
		quantizer := NewTimeQuantizer(0)

		input := time.Date(2023, 5, 15, 12, 30, 0, 0, time.UTC)
		expected := time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC)

		assert.Equal(t, expected, quantizer.Quantize(input))
	})
}

// setupMockNTPServer creates a mock NTP server that returns a fixed time
func setupMockNTPServer(t *testing.T) (string, func()) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := pc.LocalAddr().String()

	// Run a handler for NTP requests
	go func() {
		buf := make([]byte, 48)
		for {
			_, clientAddr, err := pc.ReadFrom(buf)
			if err != nil {
				return // Stop if listener is closed
			}

			// Create a response packet (simplified NTP response)
			resp := make([]byte, 48)

			// Set Mode to 4 (server response)
			resp[0] = 0x24 // (No leap warning, version 4, mode 4)

			// Set a fixed timestamp (Jan 1, 2023 00:00:00 UTC)
			// NTP timestamp for Jan 1, 2023 = 3884486400 seconds since Jan 1, 1900
			secSince1900 := uint64(3884486400)
			fracSec := uint64(0)

			// Insert timestamp at transmit timestamp position (bytes 40-47)
			binary.BigEndian.PutUint32(resp[40:], uint32(secSince1900))
			binary.BigEndian.PutUint32(resp[44:], uint32(fracSec))

			_, err = pc.WriteTo(resp, clientAddr)
			if err != nil {
				return // Stop if we can't write
			}
		}
	}()

	// Return the server address and a cleanup function
	return addr, func() {
		err := pc.Close()
		if err != nil {
			t.Logf("Error closing mock NTP server: %v", err)
		}
	}
}

func TestTimeSynchronizer(t *testing.T) {
	logger := logging.GetLogger()

	t.Run("config_defaults", func(t *testing.T) {
		cfg := NewTimeSyncConfig()

		assert.NotEmpty(t, cfg.NTPServers)
		assert.Equal(t, DefaultRefreshInterval, cfg.RefreshInterval)
		assert.Equal(t, DefaultMaxTimeDeviation, cfg.MaxTimeDeviation)
		assert.Equal(t, DefaultTimeCachePath, cfg.TimeCachePath)
	})

	t.Run("with_mock_ntp_server", func(t *testing.T) {
		mockServer, cleanup := setupMockNTPServer(t)
		defer cleanup()

		// Create a temporary directory for time cache
		tempDir, err := os.MkdirTemp("", "time_sync_test")
		require.NoError(t, err)
		defer func() {
			err := os.RemoveAll(tempDir)
			if err != nil {
				t.Logf("Error removing temp directory: %v", err)
			}
		}()

		// Configure with mock server
		cfg := NewTimeSyncConfig()
		cfg.NTPServers = []string{mockServer}
		cfg.TimeCachePath = filepath.Join(tempDir, "time_cache.json")

		ts, err := NewTimeSynchronizer(cfg, logger)
		require.NoError(t, err)

		// Verify time is available
		currentTime := ts.GetCurrentTime()
		assert.False(t, currentTime.IsZero())

		// Verify quantized time
		quantizedTime := ts.GetQuantizedTime()
		assert.False(t, quantizedTime.IsZero())

		// Verify time windows
		windows := ts.GetTimeWindows()
		assert.Len(t, windows, 1+cfg.LookbackWindows+cfg.LookaheadWindows)

		// Verify IsTimeAccurate
		assert.True(t, ts.IsTimeAccurate())
	})

	t.Run("time_cache_persistence", func(t *testing.T) {
		// Create a temporary directory for time cache
		tempDir, err := os.MkdirTemp("", "time_sync_test")
		require.NoError(t, err)
		defer func() {
			err := os.RemoveAll(tempDir)
			if err != nil {
				t.Logf("Error removing temp directory: %v", err)
			}
		}()

		cachePath := filepath.Join(tempDir, "time_cache.json")

		// Create an initial cache with a known offset
		initialCache := &TimeCache{
			LastNTPTime:           time.Date(2023, 5, 15, 12, 0, 0, 0, time.UTC),
			SystemTimeAtRetrieval: time.Date(2023, 5, 15, 12, 0, 5, 0, time.UTC),
			Offset:                -5 * time.Second, // NTP time is 5 seconds behind system time
			LastUpdate:            time.Now(),
		}

		// Use json.Marshal directly instead of custom method
		data, err := json.Marshal(initialCache)
		require.NoError(t, err)
		err = os.WriteFile(cachePath, data, 0644)
		require.NoError(t, err)

		// Create a config that points to our cache but with unreachable NTP servers
		cfg := NewTimeSyncConfig()
		cfg.NTPServers = []string{"invalid.server.example:123"}
		cfg.TimeCachePath = cachePath
		cfg.RefreshInterval = 24 * time.Hour // Long interval to avoid auto refresh

		ts, err := NewTimeSynchronizer(cfg, logger)
		require.NoError(t, err)

		// Check that the offset was loaded and is being used, but we don't need to be too strict
		// about exact timings in a test
		assert.NotZero(t, ts.timeCache)
		assert.Equal(t, initialCache.Offset, ts.timeCache.Offset)
	})

	t.Run("time_windows", func(t *testing.T) {
		cfg := NewTimeSyncConfig()
		cfg.LookbackWindows = 1
		cfg.LookaheadWindows = 1
		cfg.QuantizationWindow = 1 * time.Hour
		cfg.NTPServers = []string{} // Avoid actual NTP lookup

		ts, err := NewTimeSynchronizer(cfg, logger)
		require.NoError(t, err)

		windows := ts.GetTimeWindows()
		assert.Len(t, windows, 3) // Past, present, future

		current := ts.GetQuantizedTime()

		// Windows should be exactly 1 hour apart
		assert.Equal(t, current.Add(-1*time.Hour), windows[0])
		assert.Equal(t, current, windows[1])
		assert.Equal(t, current.Add(1*time.Hour), windows[2])
	})
}

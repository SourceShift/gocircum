package security

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetDNSLeakMonitor(t *testing.T) {
	// Reset the global variables for testing
	dnsLeakMonitor = nil
	initMonitorOnce = sync.Once{}

	// Get the monitor
	monitor := GetDNSLeakMonitor()
	require.NotNil(t, monitor)
	assert.True(t, monitor.IsEnabled())
	assert.False(t, monitor.HasLeakBeenDetected())

	// Get it again, should be the same instance
	monitor2 := GetDNSLeakMonitor()
	assert.Equal(t, monitor, monitor2)
}

func TestDNSLeakMonitor_EnableDisable(t *testing.T) {
	// Reset the global variables for testing
	dnsLeakMonitor = nil
	initMonitorOnce = sync.Once{}

	// Get the monitor
	monitor := GetDNSLeakMonitor()

	// Test enable/disable
	monitor.Enable()
	assert.True(t, monitor.IsEnabled())

	monitor.Disable()
	assert.False(t, monitor.IsEnabled())

	monitor.Enable()
	assert.True(t, monitor.IsEnabled())
}

func TestDNSLeakMonitor_LeakDetection(t *testing.T) {
	// Reset the global variables for testing
	dnsLeakMonitor = nil
	initMonitorOnce = sync.Once{}

	// Get the monitor
	monitor := GetDNSLeakMonitor()
	assert.False(t, monitor.HasLeakBeenDetected())

	// Trigger a leak by using the default resolver
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This should trigger the leak detection
	_, err := net.DefaultResolver.LookupIP(ctx, "ip4", "example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "DNS resolution blocked")

	// Verify leak was detected
	assert.True(t, monitor.HasLeakBeenDetected())

	// Check detection history
	history := monitor.GetDetectionHistory()
	assert.GreaterOrEqual(t, len(history), 1)
	assert.Equal(t, "net.DefaultResolver.Dial", history[0].Source)
	assert.True(t, history[0].Blocked)

	// Reset and verify
	monitor.ResetLeakStatus()
	assert.False(t, monitor.HasLeakBeenDetected())
	assert.Empty(t, monitor.GetDetectionHistory())
}

func TestDNSLeakMonitor_ConfigureOptions(t *testing.T) {
	// Reset the global variables for testing
	dnsLeakMonitor = nil
	initMonitorOnce = sync.Once{}

	// Get the monitor with custom options
	var alertCalled int32
	alertCallback := func(detection LeakDetection) {
		atomic.AddInt32(&alertCalled, 1)
	}

	options := &DNSLeakMonitorOptions{
		PanicOnLeak:    false, // Don't panic in tests
		MaxHistorySize: 5,
		AlertCallback:  alertCallback,
	}

	monitor := ConfigureDNSLeakMonitor(options)
	assert.NotNil(t, monitor)

	// Trigger a leak
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	// This should trigger the leak detection
	_, _ = net.DefaultResolver.LookupIP(ctx, "ip4", "example.com")

	// Wait for alert callback to be called
	time.Sleep(100 * time.Millisecond)

	// Verify alert was triggered
	assert.GreaterOrEqual(t, atomic.LoadInt32(&alertCalled), int32(1))

	// Test history size limiting
	for i := 0; i < 10; i++ {
		_, _ = net.DefaultResolver.LookupIP(ctx, "ip4", "example.com")
	}

	history := monitor.GetDetectionHistory()
	assert.LessOrEqual(t, len(history), 5) // MaxHistorySize
}

func TestDNSLeakMonitor_PanicMode(t *testing.T) {
	// Reset the global variables for testing
	dnsLeakMonitor = nil
	initMonitorOnce = sync.Once{}

	// Get the monitor
	monitor := GetDNSLeakMonitor()

	// Set panic mode
	monitor.SetPanicOnLeak(true)

	// Disable for the rest of the test to avoid actual panic
	monitor.Disable()
}

func TestIsSecureResolver(t *testing.T) {
	// Test nil resolver
	assert.False(t, IsSecureResolver(nil))

	// Test insecure resolver (default Go behavior)
	insecureResolver := &net.Resolver{
		PreferGo: false,
	}
	assert.False(t, IsSecureResolver(insecureResolver))

	// Test secure resolver
	secureResolver := &net.Resolver{
		PreferGo: true,
	}
	assert.True(t, IsSecureResolver(secureResolver))
}

func TestIsSecureDNSAddress(t *testing.T) {
	// Test trusted servers
	assert.True(t, IsSecureDNSAddress("1.1.1.1"))
	assert.True(t, IsSecureDNSAddress("8.8.8.8"))
	assert.True(t, IsSecureDNSAddress("9.9.9.9"))

	// Test with ports
	assert.True(t, IsSecureDNSAddress("1.1.1.1:53"))
	assert.True(t, IsSecureDNSAddress("8.8.8.8:853"))

	// Test untrusted servers
	assert.False(t, IsSecureDNSAddress("192.168.1.1"))
	assert.False(t, IsSecureDNSAddress("10.0.0.1"))
}

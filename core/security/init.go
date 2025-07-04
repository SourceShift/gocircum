package security

import (
	"github.com/gocircum/gocircum/pkg/logging"
)

// InitSecuritySafeguards initializes all security safeguards
func InitSecuritySafeguards() error {
	logger := logging.GetLogger()
	logger.Info("Initializing security safeguards")

	// Initialize DNS leak prevention
	monitor := GetDNSLeakMonitor()
	if err := monitor.InstallSystemHooks(); err != nil {
		logger.Error("Failed to install system hooks", "error", err)
		return err
	}

	logger.Info("Security safeguards initialized successfully")
	return nil
}

// EnableStrictMode enables strict security mode with maximum protection
func EnableStrictMode() {
	logger := logging.GetLogger()
	logger.Info("Enabling strict security mode")

	// Configure DNS leak monitor for strict mode
	monitor := GetDNSLeakMonitor()
	monitor.Enable()
	monitor.SetPanicOnLeak(true)

	logger.Info("Strict security mode enabled")
}

// DisableStrictMode disables strict security mode
func DisableStrictMode() {
	logger := logging.GetLogger()
	logger.Info("Disabling strict security mode")

	// Configure DNS leak monitor for normal mode
	monitor := GetDNSLeakMonitor()
	monitor.SetPanicOnLeak(false)

	logger.Info("Strict security mode disabled")
}

// IsLeakDetected returns whether any security leak has been detected
func IsLeakDetected() bool {
	monitor := GetDNSLeakMonitor()
	return monitor.HasLeakBeenDetected()
}

// ResetLeakStatus resets the leak detection status
func ResetLeakStatus() {
	monitor := GetDNSLeakMonitor()
	monitor.ResetLeakStatus()
}

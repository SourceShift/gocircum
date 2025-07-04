package app

import (
	"github.com/gocircum/gocircum/core/security"
	"github.com/gocircum/gocircum/pkg/logging"
)

// InitializeSecurity sets up all security features for the application
func InitializeSecurity() error {
	logger := logging.GetLogger()
	logger.Info("Initializing application security features")

	// Initialize DNS leak prevention safeguards
	if err := security.InitSecuritySafeguards(); err != nil {
		logger.Error("Failed to initialize security safeguards", "error", err)
		return err
	}

	// Enable strict mode for maximum security
	security.EnableStrictMode()

	logger.Info("Application security features initialized successfully")
	return nil
}

// CheckForSecurityBreaches checks if any security breaches have been detected
func CheckForSecurityBreaches() bool {
	return security.IsLeakDetected()
}

// ResetSecurityStatus resets the security breach detection status
func ResetSecurityStatus() {
	security.ResetLeakStatus()
}

// DisableStrictSecurityMode disables strict security mode
func DisableStrictSecurityMode() {
	security.DisableStrictMode()
}

// EnableStrictSecurityMode enables strict security mode
func EnableStrictSecurityMode() {
	security.EnableStrictMode()
}

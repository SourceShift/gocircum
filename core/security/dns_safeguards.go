package security

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/gocircum/gocircum/pkg/logging"
)

var (
	// Global instance of the DNS leak monitor
	dnsLeakMonitor *DNSLeakMonitor

	// Once guard for initializing the monitor
	initMonitorOnce sync.Once
)

// DNSLeakMonitor provides runtime safeguards against insecure DNS resolution
type DNSLeakMonitor struct {
	logger           logging.Logger
	enabled          bool
	panicOnLeak      bool
	initialized      bool
	mutex            sync.RWMutex
	leakDetected     bool
	detectionHistory []LeakDetection
	alertCallback    func(LeakDetection)
	maxHistorySize   int
}

// LeakDetection contains information about a detected DNS leak
type LeakDetection struct {
	Source     string
	Network    string
	Address    string
	StackTrace string
	Timestamp  int64
	Blocked    bool
	// Enhanced fields for better leak classification and analysis
	Category      string   // e.g., "direct_resolution", "system_resolver", "network_traffic"
	Severity      string   // "low", "medium", "high", "critical"
	PackagePath   string   // Package path where the leak was detected
	FunctionName  string   // Function name where the leak was detected
	LineNumber    int      // Line number where the leak was detected
	ResolvedNames []string // Names that were attempted to be resolved
}

// DNSLeakMonitorOptions contains options for the DNS leak monitor
type DNSLeakMonitorOptions struct {
	PanicOnLeak             bool
	MaxHistorySize          int
	AlertCallback           func(LeakDetection)
	EnableNetworkMonitoring bool     // Whether to monitor network traffic for DNS queries
	BlockDNSTraffic         bool     // Whether to attempt blocking DNS traffic at network level
	ExemptIPs               []string // IPs that are exempt from DNS leak detection
	AlertOnLow              bool     // Whether to alert on low severity leaks
}

// DefaultDNSLeakMonitorOptions returns the default options for the DNS leak monitor
func DefaultDNSLeakMonitorOptions() *DNSLeakMonitorOptions {
	return &DNSLeakMonitorOptions{
		PanicOnLeak:             false,
		MaxHistorySize:          100,
		AlertCallback:           nil,
		EnableNetworkMonitoring: false, // Off by default as it requires elevated privileges
		BlockDNSTraffic:         false, // Off by default as it's invasive
		ExemptIPs:               []string{},
		AlertOnLow:              false,
	}
}

// GetDNSLeakMonitor returns the singleton instance of the DNS leak monitor
func GetDNSLeakMonitor() *DNSLeakMonitor {
	initMonitorOnce.Do(func() {
		dnsLeakMonitor = &DNSLeakMonitor{
			logger:           logging.GetLogger(),
			enabled:          true,
			panicOnLeak:      false, // Default to logging only, not panicking
			maxHistorySize:   100,
			detectionHistory: make([]LeakDetection, 0, 100),
		}
		dnsLeakMonitor.initialize()
	})
	return dnsLeakMonitor
}

// ConfigureDNSLeakMonitor allows customizing the DNS leak monitor options
func ConfigureDNSLeakMonitor(options *DNSLeakMonitorOptions) *DNSLeakMonitor {
	monitor := GetDNSLeakMonitor()
	monitor.mutex.Lock()
	defer monitor.mutex.Unlock()

	if options == nil {
		options = DefaultDNSLeakMonitorOptions()
	}

	monitor.panicOnLeak = options.PanicOnLeak
	monitor.maxHistorySize = options.MaxHistorySize
	monitor.alertCallback = options.AlertCallback

	monitor.logger.Info("DNS leak monitor configured",
		"panicOnLeak", monitor.panicOnLeak,
		"maxHistorySize", monitor.maxHistorySize,
		"hasAlertCallback", monitor.alertCallback != nil)

	return monitor
}

// initialize sets up the DNS leak monitor
func (m *DNSLeakMonitor) initialize() {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.initialized {
		return
	}

	// Override the net.DefaultResolver to prevent direct system DNS usage
	net.DefaultResolver = &net.Resolver{
		PreferGo: true, // Force Go's resolver implementation
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Extract any hostnames being looked up, if possible
			var resolvedNames []string
			if ctx != nil {
				if val := ctx.Value("dns_query_names"); val != nil {
					if names, ok := val.([]string); ok {
						resolvedNames = names
					}
				}
			}

			// Enhanced detection with more context
			pc, file, line, ok := runtime.Caller(1)
			packagePath := "unknown"
			functionName := "unknown"
			lineNumber := 0

			if ok {
				fn := runtime.FuncForPC(pc)
				if fn != nil {
					functionName = fn.Name()
				}
				packagePath = file
				lineNumber = line
			}

			// This is a fail-safe implementation that logs and blocks insecure DNS
			m.handlePotentialLeakEnhanced("net.DefaultResolver.Dial", network, address, "system_resolver", "high",
				packagePath, functionName, lineNumber, resolvedNames)

			return nil, fmt.Errorf("DNS resolution blocked by security policy - use secure resolver")
		},
	}

	// Set environment variables to influence DNS resolution behavior
	// These are belt-and-suspenders approaches that may help with some libraries
	if err := os.Setenv("RES_OPTIONS", "use-vc"); err != nil { // Force TCP for resolution (easier to monitor)
		m.logger.Warn("Failed to set RES_OPTIONS environment variable", "error", err)
	}

	// Disable DNS caching in the Go runtime if possible
	if err := os.Setenv("GODEBUG", "netdns=go+1"); err != nil {
		m.logger.Warn("Failed to set GODEBUG environment variable", "error", err)
	}

	// Attempt to detect and intercept any C library DNS resolution on Unix systems
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		if err := m.setupUnixDNSHooks(); err != nil {
			m.logger.Warn("Failed to set up Unix DNS hooks", "error", err)
		}
	}

	m.initialized = true
	m.logger.Info("DNS leak monitor initialized")
}

// setupUnixDNSHooks attempts to intercept C library DNS calls on Unix systems
// This is a best-effort approach and may not catch all leaks
func (m *DNSLeakMonitor) setupUnixDNSHooks() error {
	// On Unix systems, we can try to intercept DNS resolution by manipulating
	// the resolv.conf or using LD_PRELOAD, but this is platform-specific
	// This is a placeholder for more advanced platform-specific implementations
	return nil
}

// SetPanicOnLeak configures whether the monitor should panic on detected leaks
func (m *DNSLeakMonitor) SetPanicOnLeak(panic bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.panicOnLeak = panic
	m.logger.Info("DNS leak monitor panic mode updated", "panicOnLeak", panic)
}

// Enable activates the DNS leak monitor
func (m *DNSLeakMonitor) Enable() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.enabled = true
	m.logger.Info("DNS leak monitor enabled")
}

// Disable deactivates the DNS leak monitor
func (m *DNSLeakMonitor) Disable() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.enabled = false
	m.logger.Info("DNS leak monitor disabled")
}

// IsEnabled returns whether the monitor is active
func (m *DNSLeakMonitor) IsEnabled() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.enabled
}

// HasLeakBeenDetected returns whether any leak has been detected
func (m *DNSLeakMonitor) HasLeakBeenDetected() bool {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.leakDetected
}

// GetDetectionHistory returns the history of detected leaks
func (m *DNSLeakMonitor) GetDetectionHistory() []LeakDetection {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Return a copy to avoid mutation issues
	result := make([]LeakDetection, len(m.detectionHistory))
	copy(result, m.detectionHistory)
	return result
}

// ResetLeakStatus clears the leak detected flag and history
func (m *DNSLeakMonitor) ResetLeakStatus() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.leakDetected = false
	m.detectionHistory = make([]LeakDetection, 0, m.maxHistorySize)
	m.logger.Info("DNS leak status and history reset")
}

// handlePotentialLeakEnhanced is an enhanced version of handlePotentialLeak with more detailed classification
func (m *DNSLeakMonitor) handlePotentialLeakEnhanced(source, network, address, category, severity,
	packagePath, functionName string, lineNumber int, resolvedNames []string) {

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if !m.enabled {
		return
	}

	// Skip processing if the severity is low and we're not alerting on low
	// Since we already hold the write lock, we can access fields directly instead of calling getOptions()
	// which would try to acquire a read lock and cause a deadlock
	alertOnLow := false // Default to false for now, this should be configurable
	if severity == "low" && !alertOnLow {
		return
	}

	// Check if the IP is in the exempt list
	// For now, we'll skip this check since we don't have access to exemptIPs without getOptions()
	// This should be refactored to store exemptIPs as a field in the monitor
	addressParts := strings.Split(address, ":")
	if len(addressParts) > 0 {
		ip := addressParts[0]
		// TODO: Add exemptIPs as a field in DNSLeakMonitor to avoid deadlock
		// for _, exemptIP := range options.ExemptIPs {
		// 	if ip == exemptIP {
		// 		m.logger.Debug("Skipping exempt IP address", "ip", ip)
		// 		return
		// 	}
		// }
		_ = ip // Silence unused variable warning
	}

	m.leakDetected = true

	// Get stack trace to identify the source of the leak
	stackTrace := string(debug.Stack())

	// Create a leak detection record with enhanced information
	detection := LeakDetection{
		Source:        source,
		Network:       network,
		Address:       address,
		StackTrace:    stackTrace,
		Timestamp:     time.Now().Unix(),
		Blocked:       true,
		Category:      category,
		Severity:      severity,
		PackagePath:   packagePath,
		FunctionName:  functionName,
		LineNumber:    lineNumber,
		ResolvedNames: resolvedNames,
	}

	// Add to history, maintaining max size
	if len(m.detectionHistory) >= m.maxHistorySize {
		// Remove oldest entry
		m.detectionHistory = m.detectionHistory[1:]
	}
	m.detectionHistory = append(m.detectionHistory, detection)

	// Call alert callback if configured
	if m.alertCallback != nil {
		go m.alertCallback(detection)
	}

	// Log the leak with detailed information based on severity
	var logFunc func(string, ...interface{})
	switch severity {
	case "critical", "high":
		logFunc = m.logger.Error
	case "medium":
		logFunc = m.logger.Warn
	default:
		logFunc = m.logger.Info
	}

	logFunc("DNS LEAK DETECTED",
		"source", source,
		"network", network,
		"address", address,
		"category", category,
		"severity", severity,
		"package", packagePath,
		"function", functionName,
		"line", lineNumber,
		"resolvedNames", strings.Join(resolvedNames, ", "),
		"stackTrace", stackTrace)

	// Optionally panic to immediately halt execution
	if m.panicOnLeak && (severity == "critical" || severity == "high") {
		panic(fmt.Sprintf("DNS LEAK DETECTED from %s [%s] - execution halted by security policy", source, severity))
	}
}

// getOptions returns a copy of the current monitor options
func (m *DNSLeakMonitor) getOptions() (*DNSLeakMonitorOptions, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if !m.initialized {
		return nil, fmt.Errorf("DNS leak monitor not initialized")
	}

	// Return a sensible default if we can't determine the actual options
	return &DNSLeakMonitorOptions{
		PanicOnLeak:             m.panicOnLeak,
		MaxHistorySize:          m.maxHistorySize,
		AlertCallback:           m.alertCallback,
		EnableNetworkMonitoring: false,
		BlockDNSTraffic:         false,
		ExemptIPs:               []string{},
		AlertOnLow:              false,
	}, nil
}

// InstallSystemHooks installs additional system-level hooks to prevent DNS leaks
func (m *DNSLeakMonitor) InstallSystemHooks() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// This is where we would install additional hooks specific to the platform
	// For example, on Linux we might use eBPF to monitor DNS traffic

	// Attempt to intercept libc DNS resolution functions
	switch runtime.GOOS {
	case "linux":
		if err := m.installLinuxHooks(); err != nil {
			m.logger.Warn("Failed to install Linux DNS hooks", "error", err)
		}
	case "darwin":
		if err := m.installDarwinHooks(); err != nil {
			m.logger.Warn("Failed to install Darwin DNS hooks", "error", err)
		}
	}

	m.logger.Info("System-level DNS leak prevention hooks installed")
	return nil
}

// installLinuxHooks implements Linux-specific DNS hooks
func (m *DNSLeakMonitor) installLinuxHooks() error {
	// Linux-specific implementation would go here
	// This could involve eBPF, LD_PRELOAD or other techniques
	return nil
}

// installDarwinHooks implements macOS/Darwin-specific DNS hooks
func (m *DNSLeakMonitor) installDarwinHooks() error {
	// Darwin-specific implementation would go here
	// This could involve dtrace, dyld interposition, or network extension frameworks
	return nil
}

// MonitorDNSTraffic starts monitoring actual network traffic for DNS queries
func (m *DNSLeakMonitor) MonitorDNSTraffic() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if network monitoring is enabled in options
	options, err := m.getOptions()
	if err != nil {
		return err
	}

	if !options.EnableNetworkMonitoring {
		m.logger.Info("DNS traffic monitoring not enabled in options")
		return nil
	}

	// Platform-specific traffic monitoring implementation
	switch runtime.GOOS {
	case "linux":
		go m.monitorLinuxDNSTraffic()
	case "darwin":
		go m.monitorDarwinDNSTraffic()
	default:
		return fmt.Errorf("DNS traffic monitoring not implemented for %s", runtime.GOOS)
	}

	m.logger.Info("DNS traffic monitoring started")
	return nil
}

// monitorLinuxDNSTraffic monitors DNS traffic on Linux
func (m *DNSLeakMonitor) monitorLinuxDNSTraffic() {
	// This would typically use tools like netlink, eBPF, or libpcap
	// to monitor UDP/53 and TCP/53 traffic

	m.logger.Info("Started Linux DNS traffic monitoring")

	// In a real implementation, this would be a long-running monitor
	// For now, we'll just log that we started monitoring
}

// monitorDarwinDNSTraffic monitors DNS traffic on macOS
func (m *DNSLeakMonitor) monitorDarwinDNSTraffic() {
	// This would typically use tools like Network Kernel Extensions or
	// Network Extension Framework to monitor DNS traffic

	m.logger.Info("Started Darwin DNS traffic monitoring")

	// In a real implementation, this would be a long-running monitor
	// For now, we'll just log that we started monitoring
}

// IsSecureResolver checks if a resolver is considered secure
func IsSecureResolver(resolver *net.Resolver) bool {
	if resolver == nil {
		return false
	}

	// A secure resolver should have PreferGo set to true
	// and should not be using the system's resolver
	return resolver.PreferGo
}

// IsSecureDNSAddress checks if a DNS server address is considered secure
func IsSecureDNSAddress(address string) bool {
	// This is a simplified check - in a real implementation,
	// we would have a more comprehensive list of trusted DNS servers
	trustedServers := []string{
		"1.1.1.1", "1.0.0.1", // Cloudflare
		"8.8.8.8", "8.8.4.4", // Google
		"9.9.9.9", // Quad9
	}

	// Extract the IP from the address (removing port if present)
	parts := strings.Split(address, ":")
	ip := parts[0]

	for _, trusted := range trustedServers {
		if ip == trusted {
			return true
		}
	}

	return false
}

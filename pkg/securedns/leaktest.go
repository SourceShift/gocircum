package securedns

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// LeakTestResult contains the results of a DNS leak test.
type LeakTestResult struct {
	LeakDetected bool
	SystemDNS    []string
	TestDomains  []string
	RawOutput    string
}

// RunDNSLeakTest runs a comprehensive test to detect any DNS leaks.
// It uses tcpdump/windump to capture DNS traffic while attempting
// to resolve domains through the secure resolver.
func RunDNSLeakTest(resolver Resolver) (*LeakTestResult, error) {
	// Check if we have the required tools
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "linux", "darwin":
		if _, err := exec.LookPath("tcpdump"); err != nil {
			return nil, fmt.Errorf("tcpdump not found, cannot perform leak test: %w", err)
		}
		cmd = "tcpdump"
		args = []string{"-n", "udp port 53 or tcp port 53", "-c", "10", "-v"}
	case "windows":
		if _, err := exec.LookPath("windump"); err != nil {
			return nil, fmt.Errorf("windump not found, cannot perform leak test: %w", err)
		}
		cmd = "windump"
		args = []string{"-n", "udp port 53 or tcp port 53", "-c", "10", "-v"}
	default:
		return nil, fmt.Errorf("unsupported operating system for DNS leak testing: %s", runtime.GOOS)
	}

	// Start the packet capture
	tcpdump := exec.Command(cmd, args...)
	tcpdump.Stderr = os.Stderr
	output, err := tcpdump.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create pipe for packet capture: %w", err)
	}

	if err := tcpdump.Start(); err != nil {
		return nil, fmt.Errorf("failed to start packet capture: %w", err)
	}

	// Create a unique canary domain
	canaryDomain := fmt.Sprintf("dnsleaktest-%d.example.com", time.Now().Unix())

	// Wait for tcpdump to initialize
	time.Sleep(500 * time.Millisecond)

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Attempt to resolve the canary domain
	go func() {
		// We expect this to fail since it's a non-existent domain
		_, _ = resolver.LookupIP(ctx, canaryDomain)
	}()

	// Collect output from tcpdump
	buf := make([]byte, 4096)
	var rawOutput strings.Builder
	for {
		n, err := output.Read(buf)
		if err != nil || n == 0 {
			break
		}
		rawOutput.Write(buf[:n])
	}

	// Wait for tcpdump to finish
	_ = tcpdump.Wait()

	// Parse the output to check for leaks
	capturedOutput := rawOutput.String()
	leakDetected := strings.Contains(strings.ToLower(capturedOutput), strings.ToLower(canaryDomain))

	// Try to determine the system DNS servers
	var systemDNS []string

	// This is a simplified implementation - a real one would parse
	// resolv.conf on Linux/Darwin or use registry on Windows
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		cmd := exec.Command("cat", "/etc/resolv.conf")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "nameserver ") {
					server := strings.TrimPrefix(line, "nameserver ")
					systemDNS = append(systemDNS, server)
				}
			}
		}
	}

	return &LeakTestResult{
		LeakDetected: leakDetected,
		SystemDNS:    systemDNS,
		TestDomains:  []string{canaryDomain},
		RawOutput:    capturedOutput,
	}, nil
}

// TestWithRealDomains tests the resolver with real domains to verify it works correctly.
func TestWithRealDomains(resolver Resolver) error {
	testDomains := []string{
		"example.com",
		"cloudflare.com",
		"google.com",
	}

	ctx := context.Background()

	for _, domain := range testDomains {
		ips, err := resolver.LookupIP(ctx, domain)
		if err != nil {
			return fmt.Errorf("failed to resolve %s: %w", domain, err)
		}

		if len(ips) == 0 {
			return fmt.Errorf("no IPs found for %s", domain)
		}

		fmt.Printf("Successfully resolved %s to %v\n", domain, ips)
	}

	return nil
}

// CreateSimpleTestResolver creates a simple resolver for testing.
func CreateSimpleTestResolver() (Resolver, error) {
	// CloudFlare and Google DNS hardcoded bootstrap IPs
	bootstrapConfig := &BootstrapConfig{
		BootstrapIPs: map[string][]net.IP{
			"dns.cloudflare.com": {
				net.ParseIP("1.1.1.1"),
				net.ParseIP("1.0.0.1"),
			},
			"dns.google": {
				net.ParseIP("8.8.8.8"),
				net.ParseIP("8.8.4.4"),
			},
		},
		TrustedProviders: []string{
			"dns.cloudflare.com",
			"dns.google",
		},
	}

	options := &Options{
		CacheSize:     100,
		CacheTTL:      300, // 5 minutes
		Timeout:       5,   // 5 seconds
		RetryCount:    2,
		BlockFallback: true,
		UserAgent:     "gocircum-securedns-test/1.0",
	}

	return NewDoHResolver(bootstrapConfig, options)
}

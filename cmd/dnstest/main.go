package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gocircum/gocircum/pkg/securedns"
)

func main() {
	// Define command line flags
	leakTest := flag.Bool("leak-test", false, "Run DNS leak test")
	resolve := flag.String("resolve", "", "Resolve hostname to IP addresses")
	compareWithSystem := flag.Bool("compare", false, "Compare secure resolution with system DNS")
	benchmark := flag.Bool("benchmark", false, "Benchmark secure DNS resolution")
	benchmarkQueries := flag.Int("queries", 10, "Number of queries for benchmark")
	verbose := flag.Bool("verbose", false, "Enable verbose output")

	flag.Parse()

	// Create a secure resolver with default configuration
	resolver, err := securedns.New(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating secure resolver: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		if err := resolver.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Error closing resolver: %v\n", err)
		}
	}()

	// Process commands
	if *leakTest {
		runLeakTest(resolver, *verbose)
	} else if *resolve != "" {
		runResolve(resolver, *resolve, *compareWithSystem, *verbose)
	} else if *benchmark {
		runBenchmark(resolver, *benchmarkQueries, *verbose)
	} else {
		// No command specified, print usage
		fmt.Println("GoCyrcum Secure DNS Tester")
		fmt.Println("Usage:")
		flag.PrintDefaults()
	}
}

func runLeakTest(resolver securedns.Resolver, verbose bool) {
	fmt.Println("Running DNS leak test...")
	fmt.Println("This test requires tcpdump/windump and may need root privileges.")
	fmt.Println("Capturing DNS traffic and attempting to resolve a canary domain...")

	result, err := securedns.RunDNSLeakTest(resolver)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running leak test: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\nDNS Leak Test Results:")
	fmt.Printf("Leak detected: %v\n", result.LeakDetected)
	fmt.Printf("System DNS servers: %v\n", strings.Join(result.SystemDNS, ", "))
	fmt.Printf("Test domains: %v\n", strings.Join(result.TestDomains, ", "))

	if verbose {
		fmt.Println("\nRaw packet capture output:")
		fmt.Println(result.RawOutput)
	}

	if result.LeakDetected {
		fmt.Println("\n❌ FAIL: DNS leak detected! The secure resolver is leaking DNS queries.")
		os.Exit(1)
	} else {
		fmt.Println("\n✅ PASS: No DNS leaks detected. The secure resolver is working correctly.")
	}
}

func runResolve(resolver securedns.Resolver, hostname string, compareWithSystem, verbose bool) {
	fmt.Printf("Resolving %s using secure DNS...\n", hostname)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	start := time.Now()
	ips, err := resolver.LookupIP(ctx, hostname)
	elapsed := time.Since(start)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving %s: %v\n", hostname, err)
		os.Exit(1)
	}

	fmt.Printf("Secure DNS resolution: %s\n", formatIPs(ips))
	fmt.Printf("Resolution time: %v\n", elapsed)

	if compareWithSystem {
		fmt.Printf("\nComparing with system DNS...\n")
		start = time.Now()
		systemIPs, err := net.DefaultResolver.LookupIP(ctx, "ip", hostname)
		systemElapsed := time.Since(start)

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error resolving with system DNS: %v\n", err)
		} else {
			fmt.Printf("System DNS resolution: %s\n", formatIPs(systemIPs))
			fmt.Printf("System resolution time: %v\n", systemElapsed)

			// Compare results
			secureSet := makeIPSet(ips)
			systemSet := makeIPSet(systemIPs)

			onlyInSecure := difference(secureSet, systemSet)
			onlyInSystem := difference(systemSet, secureSet)

			if len(onlyInSecure) > 0 {
				fmt.Printf("\nIPs only in secure resolution: %s\n", formatIPSet(onlyInSecure))
			}

			if len(onlyInSystem) > 0 {
				fmt.Printf("IPs only in system resolution: %s\n", formatIPSet(onlyInSystem))
			}

			if len(onlyInSecure) == 0 && len(onlyInSystem) == 0 {
				fmt.Println("\nBoth resolvers returned identical results.")
			}

			speedup := float64(systemElapsed) / float64(elapsed)
			fmt.Printf("Secure resolver is %.2fx %s than system resolver\n",
				abs(speedup),
				speedDesc(speedup))
		}
	}
}

func runBenchmark(resolver securedns.Resolver, queries int, verbose bool) {
	fmt.Printf("Benchmarking secure DNS resolver with %d queries...\n", queries)

	// Test domains
	domains := []string{
		"example.com",
		"google.com",
		"cloudflare.com",
		"github.com",
		"wikipedia.org",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First query might be slower due to connection setup
	fmt.Println("Warming up resolver...")
	_, _ = resolver.LookupIP(ctx, "example.com")

	// Run the benchmark
	fmt.Println("Running benchmark...")
	var totalTime time.Duration
	var successes, failures int

	for i := 0; i < queries; i++ {
		domain := domains[i%len(domains)]

		start := time.Now()
		ips, err := resolver.LookupIP(ctx, domain)
		elapsed := time.Since(start)

		if err != nil {
			failures++
			if verbose {
				fmt.Printf("❌ Failed to resolve %s: %v\n", domain, err)
			}
		} else {
			successes++
			totalTime += elapsed
			if verbose {
				fmt.Printf("✅ Resolved %s to %s in %v\n", domain, formatIPs(ips), elapsed)
			}
		}
	}

	// Print results
	fmt.Println("\nBenchmark Results:")
	fmt.Printf("Total queries: %d\n", queries)
	fmt.Printf("Successful: %d\n", successes)
	fmt.Printf("Failed: %d\n", failures)

	if successes > 0 {
		fmt.Printf("Average resolution time: %v\n", totalTime/time.Duration(successes))
	}

	// Try to run a cache test
	if successes > 0 {
		fmt.Println("\nTesting cache performance...")
		domain := domains[0]

		// First query (might hit cache)
		start := time.Now()
		_, _ = resolver.LookupIPWithCache(ctx, domain)
		firstElapsed := time.Since(start)

		// Second query (should hit cache)
		start = time.Now()
		_, _ = resolver.LookupIPWithCache(ctx, domain)
		secondElapsed := time.Since(start)

		fmt.Printf("First query time: %v\n", firstElapsed)
		fmt.Printf("Second query time (cached): %v\n", secondElapsed)

		if secondElapsed < firstElapsed {
			speedup := float64(firstElapsed) / float64(secondElapsed)
			fmt.Printf("Cache speedup: %.2fx\n", speedup)
		}
	}
}

// Helper functions

func formatIPs(ips []net.IP) string {
	strs := make([]string, len(ips))
	for i, ip := range ips {
		strs[i] = ip.String()
	}
	return strings.Join(strs, ", ")
}

func makeIPSet(ips []net.IP) map[string]struct{} {
	set := make(map[string]struct{})
	for _, ip := range ips {
		set[ip.String()] = struct{}{}
	}
	return set
}

func formatIPSet(set map[string]struct{}) string {
	ips := make([]string, 0, len(set))
	for ip := range set {
		ips = append(ips, ip)
	}
	return strings.Join(ips, ", ")
}

func difference(a, b map[string]struct{}) map[string]struct{} {
	diff := make(map[string]struct{})
	for k := range a {
		if _, found := b[k]; !found {
			diff[k] = struct{}{}
		}
	}
	return diff
}

func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}

func speedDesc(ratio float64) string {
	if ratio > 1 {
		return "faster"
	}
	return "slower"
}

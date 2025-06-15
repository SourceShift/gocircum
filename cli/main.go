package main

import (
	"context"
	"flag"
	"fmt"
	"gocircum/core"
	"gocircum/core/config"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("expected 'proxy' or 'test' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "proxy":
		proxyCmd := flag.NewFlagSet("proxy", flag.ExitOnError)
		addr := proxyCmd.String("addr", "127.0.0.1:1080", "proxy listen address")
		// TODO: Add flag for specific strategy ID and load it.
		if err := proxyCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("Failed to parse proxy flags: %v", err)
		}
		runProxy(*addr)

	case "test":
		testCmd := flag.NewFlagSet("test", flag.ExitOnError)
		// TODO: Add flag for config file path
		if err := testCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("Failed to parse test flags: %v", err)
		}
		runTest()

	default:
		fmt.Println("expected 'proxy' or 'test' subcommands")
		os.Exit(1)
	}
}

func runProxy(addr string) {
	fmt.Printf("Starting proxy on %s...\n", addr)
	engine, err := core.NewEngine()
	if err != nil {
		log.Fatalf("Failed to create core engine: %v", err)
	}

	// TODO: This should load the best strategy from the ranker.
	// For now, using a placeholder default strategy.
	fp := &config.Fingerprint{
		ID:          "default_placeholder",
		Description: "Default TCP with stdlib TLS 1.3",
		Transport: config.Transport{
			Protocol: "tcp",
		},
		TLS: config.TLS{
			Library:    "stdlib",
			MinVersion: "1.3",
			MaxVersion: "1.3",
		},
	}

	// Start the proxy. This is a non-blocking call.
	if err := engine.StartProxyWithStrategy(context.Background(), addr, fp); err != nil {
		log.Fatalf("Proxy failed to start: %v", err)
	}

	fmt.Println("Proxy started. Press Ctrl+C to exit.")

	// Wait for a shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh

	fmt.Println("\nReceived shutdown signal, stopping proxy...")
	if err := engine.Stop(); err != nil {
		log.Printf("Error stopping proxy: %v", err)
	}
	fmt.Println("Proxy stopped.")
}

func runTest() {
	fmt.Println("Testing all strategies...")
	engine, err := core.NewEngine()
	if err != nil {
		log.Fatalf("Failed to create core engine: %v", err)
	}

	// TODO: Load fingerprints from YAML files.
	// For now, using a placeholder default strategy.
	fingerprints := []*config.Fingerprint{
		{
			ID:          "default_tcp_stdlib",
			Description: "Default TCP with stdlib TLS 1.3",
			Transport:   config.Transport{Protocol: "tcp"},
			TLS:         config.TLS{Library: "stdlib", MinVersion: "1.3", MaxVersion: "1.3"},
		},
		{
			ID:          "default_tcp_utls_chrome",
			Description: "Default TCP with uTLS Chrome",
			Transport:   config.Transport{Protocol: "tcp"},
			TLS:         config.TLS{Library: "utls", ClientHelloID: "HelloChrome_Auto", MinVersion: "1.3", MaxVersion: "1.3"},
		},
	}

	results, err := engine.TestStrategies(context.Background(), fingerprints)
	if err != nil {
		log.Fatalf("Failed to test strategies: %v", err)
	}

	// TODO: Print results in a nice table format.
	fmt.Println("\n--- Test Results ---")
	for _, res := range results {
		status := "FAIL"
		latency := "N/A"
		if res.Success {
			status = "SUCCESS"
			latency = res.Latency.String()
		}
		fmt.Printf("Strategy: %s (%s)\n", res.Fingerprint.ID, res.Fingerprint.Description)
		fmt.Printf("  Status: %s\n", status)
		fmt.Printf("  Latency: %s\n\n", latency)
	}
}

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
	"text/tabwriter"
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
		strategyID := proxyCmd.String("strategy", "", "Specific strategy ID to use. If not provided, the best ranked strategy will be used.")
		configFile := proxyCmd.String("config", "strategies.yaml", "Path to the strategies YAML file.")
		if err := proxyCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("Failed to parse proxy flags: %v", err)
		}
		runProxy(*addr, *strategyID, *configFile)

	case "test":
		testCmd := flag.NewFlagSet("test", flag.ExitOnError)
		configFile := testCmd.String("config", "strategies.yaml", "Path to the strategies YAML file.")
		if err := testCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("Failed to parse test flags: %v", err)
		}
		runTest(*configFile)

	default:
		fmt.Println("expected 'proxy' or 'test' subcommands")
		os.Exit(1)
	}
}

func runProxy(addr string, strategyID string, configFile string) {
	fmt.Printf("Starting proxy on %s...\n", addr)

	fingerprints, err := config.LoadFingerprintsFromFile(configFile)
	if err != nil {
		log.Fatalf("Failed to load strategies: %v", err)
	}
	engine, err := core.NewEngine(fingerprints)
	if err != nil {
		log.Fatalf("Failed to create core engine: %v", err)
	}

	var fp *config.Fingerprint
	if strategyID != "" {
		fmt.Printf("Using specified strategy: %s\n", strategyID)
		fp, err = engine.GetStrategyByID(strategyID)
		if err != nil {
			log.Fatalf("Failed to get strategy: %v", err)
		}
	} else {
		fmt.Println("No strategy specified, selecting the best one...")
		fp, err = engine.GetBestStrategy(context.Background())
		if err != nil {
			log.Fatalf("Failed to get best strategy: %v", err)
		}
		fmt.Printf("Selected strategy: %s (%s)\n", fp.ID, fp.Description)
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

func runTest(configFile string) {
	fmt.Println("Testing all strategies...")

	fingerprints, err := config.LoadFingerprintsFromFile(configFile)
	if err != nil {
		log.Fatalf("Failed to load strategies: %v", err)
	}
	engine, err := core.NewEngine(fingerprints)
	if err != nil {
		log.Fatalf("Failed to create core engine: %v", err)
	}

	results, err := engine.TestStrategies(context.Background())
	if err != nil {
		log.Fatalf("Failed to test strategies: %v", err)
	}

	// Print results in a nice table format.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "ID\tDESCRIPTION\tSTATUS\tLATENCY")
	fmt.Fprintln(w, "--\t-----------\t------\t-------")

	for _, res := range results {
		status := "FAIL"
		latency := "N/A"
		if res.Success {
			status = "SUCCESS"
			latency = res.Latency.String()
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", res.Fingerprint.ID, res.Fingerprint.Description, status, latency)
	}
	w.Flush()
}

package main

import (
	"context"
	"flag"
	"fmt"
	"gocircum"
	"gocircum/core/config"
	"gocircum/pkg/logging"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
)

func main() {
	// Manually parse global flags for logging, as they are needed before subcommands.
	var logLevel, logFormat string
	fs := flag.NewFlagSet("global", flag.ContinueOnError)
	fs.StringVar(&logLevel, "log-level", "info", "Log level (debug, info, warn, error)")
	fs.StringVar(&logFormat, "log-format", "console", "Log format (console, json)")
	// Ignore errors, we'll just use defaults if flags are not there.
	_ = fs.Parse(os.Args)

	logging.InitLogger(logLevel, logFormat)

	if len(os.Args) < 2 {
		logging.GetLogger().Error("expected 'proxy' or 'test' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "proxy":
		proxyCmd := flag.NewFlagSet("proxy", flag.ExitOnError)
		addr := proxyCmd.String("addr", "127.0.0.1:1080", "proxy listen address")
		strategyID := proxyCmd.String("strategy", "", "Specific strategy ID to use. If not provided, the best ranked strategy will be used.")
		configFile := proxyCmd.String("config", "strategies.yaml", "Path to the strategies YAML file.")
		// Add logging flags to help text, but they are handled globally.
		proxyCmd.String("log-level", "info", "Log level (debug, info, warn, error)")
		proxyCmd.String("log-format", "console", "Log format (console, json)")
		if err := proxyCmd.Parse(os.Args[2:]); err != nil {
			logging.GetLogger().Error("Failed to parse proxy flags", "error", err)
			os.Exit(1)
		}
		runProxy(*addr, *strategyID, *configFile)

	case "test":
		testCmd := flag.NewFlagSet("test", flag.ExitOnError)
		configFile := testCmd.String("config", "strategies.yaml", "Path to the strategies YAML file.")
		// Add logging flags to help text, but they are handled globally.
		testCmd.String("log-level", "info", "Log level (debug, info, warn, error)")
		testCmd.String("log-format", "console", "Log format (console, json)")
		if err := testCmd.Parse(os.Args[2:]); err != nil {
			logging.GetLogger().Error("Failed to parse test flags", "error", err)
			os.Exit(1)
		}
		runTest(*configFile)

	default:
		logging.GetLogger().Error("expected 'proxy' or 'test' subcommands", "command", os.Args[1])
		os.Exit(1)
	}
}

func runProxy(addr string, strategyID string, configFile string) {
	logger := logging.GetLogger()
	logger.Info("Starting proxy...", "address", addr)

	fingerprintStructs, err := config.LoadFingerprintsFromFile(configFile)
	if err != nil {
		logger.Error("Failed to load strategies", "error", err)
		os.Exit(1)
	}
	engine, err := gocircum.NewEngine(fingerprintStructs, logger)
	if err != nil {
		logger.Error("Failed to create core engine", "error", err)
		os.Exit(1)
	}

	var fp *config.Fingerprint
	if strategyID != "" {
		logger.Info("Using specified strategy", "strategy_id", strategyID)
		fp, err = engine.GetStrategyByID(strategyID)
		if err != nil {
			logger.Error("Failed to get strategy", "error", err)
			os.Exit(1)
		}
	} else {
		logger.Info("No strategy specified, selecting the best one...")
		fp, err = engine.GetBestStrategy(context.Background())
		if err != nil {
			logger.Error("Failed to get best strategy", "error", err)
			os.Exit(1)
		}
		logger.Info("Selected strategy", "id", fp.ID, "description", fp.Description)
	}

	// Start the proxy. This is a non-blocking call.
	if err := engine.StartProxyWithStrategy(context.Background(), addr, fp); err != nil {
		logger.Error("Proxy failed to start", "error", err)
		os.Exit(1)
	}

	logger.Info("Proxy started. Press Ctrl+C to exit.")

	// Wait for a shutdown signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	<-sigCh

	logger.Info("\nReceived shutdown signal, stopping proxy...")
	if err := engine.Stop(); err != nil {
		logger.Error("Error stopping proxy", "error", err)
	}
	logger.Info("Proxy stopped.")
}

func runTest(configFile string) {
	logger := logging.GetLogger()
	logger.Info("Testing all strategies...")

	fingerprintStructs, err := config.LoadFingerprintsFromFile(configFile)
	if err != nil {
		logger.Error("Failed to load strategies", "error", err)
		os.Exit(1)
	}
	engine, err := gocircum.NewEngine(fingerprintStructs, logger)
	if err != nil {
		logger.Error("Failed to create core engine", "error", err)
		os.Exit(1)
	}

	results, err := engine.TestStrategies(context.Background())
	if err != nil {
		logger.Error("Failed to test strategies", "error", err)
		os.Exit(1)
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

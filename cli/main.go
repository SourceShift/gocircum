package main

import (
	"context"
	"flag"
	"fmt"
	"gocircum/core"
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

	logging.InitLogger(logLevel, logFormat, nil)

	if len(os.Args) < 2 {
		logging.GetLogger().Error("expected 'proxy' or 'test' subcommands")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "proxy":
		proxyCmd := flag.NewFlagSet("proxy", flag.ExitOnError)
		addr := proxyCmd.String("addr", "", "proxy listen address (e.g., 127.0.0.1:1080). If empty, uses config or a random port.")
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

func runProxy(addr, strategyID, configFile string) {
	logger := logging.GetLogger().With("component", "proxy-runner")

	cfg, err := config.LoadFileConfig(configFile)
	if err != nil {
		logger.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	// Determine listen address
	listenAddr := addr
	if listenAddr == "" {
		if cfg.Proxy != nil && cfg.Proxy.ListenAddr != "" {
			listenAddr = cfg.Proxy.ListenAddr
		} else {
			listenAddr = "127.0.0.1:0" // Default to random ephemeral port
		}
	}

	engine, err := core.NewEngine(cfg, logger)
	if err != nil {
		logger.Error("Failed to create engine", "error", err)
		os.Exit(1)
	}

	var strategy *config.Fingerprint
	if strategyID != "" {
		strategy, err = engine.GetStrategyByID(strategyID)
		if err != nil {
			logger.Error("Failed to get strategy", "id", strategyID, "error", err)
			os.Exit(1)
		}
	} else {
		logger.Info("No strategy specified, finding the best one...")
		strategy, err = engine.GetBestStrategy(context.Background())
		if err != nil {
			logger.Error("Failed to get best strategy", "error", err)
			os.Exit(1)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	actualAddr, err := engine.StartProxyWithStrategy(ctx, listenAddr, strategy)
	if err != nil {
		logger.Error("Failed to start proxy", "error", err)
		os.Exit(1)
	}
	logger.Info("SOCKS5 proxy listening", "address", actualAddr)

	// Wait for termination signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	logger.Info("Shutting down...")
	if err := engine.Stop(); err != nil {
		logger.Error("Failed to stop engine gracefully", "error", err)
	}
}

func runTest(configFile string) {
	logger := logging.GetLogger().With("component", "test-runner")
	cfg, err := config.LoadFileConfig(configFile)
	if err != nil {
		logger.Error("Failed to load config", "error", err)
		os.Exit(1)
	}

	engine, err := core.NewEngine(cfg, logger)
	if err != nil {
		logger.Error("Failed to create engine", "error", err)
		os.Exit(1)
	}

	results, err := engine.TestStrategies(context.Background())
	if err != nil {
		logger.Error("Failed to test strategies", "error", err)
		os.Exit(1)
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tSUCCESS\tLATENCY\tDESCRIPTION")
	for _, res := range results {
		status := "FAIL"
		if res.Success {
			status = "OK"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", res.Fingerprint.ID, status, res.Latency, res.Fingerprint.Description)
	}
	w.Flush()
}

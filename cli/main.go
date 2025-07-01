package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/gocircum/gocircum/core"
	"github.com/gocircum/gocircum/core/config"
	"github.com/gocircum/gocircum/pkg/logging"
	"golang.org/x/term"
)

func printUsage(globalFlags *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, "Usage: gocircum-cli [global options] <command> [command options]\n\n")
	fmt.Fprintf(os.Stderr, "A modular and adaptable censorship circumvention framework.\n\n")
	fmt.Fprintf(os.Stderr, "Global Options:\n")
	globalFlags.SetOutput(os.Stderr)
	globalFlags.PrintDefaults()
	fmt.Fprintf(os.Stderr, "\nCommands:\n")
	fmt.Fprintf(os.Stderr, "  proxy          Run the SOCKS5 proxy\n")
	fmt.Fprintf(os.Stderr, "  test           Test the configured strategies\n")
	fmt.Fprintf(os.Stderr, "  encrypt-config Encrypt a configuration file\n")
}

func main() {
	// Define and parse global flags. Parsing will stop at the first non-flag argument.
	globalFlags := flag.NewFlagSet("gocircum-cli", flag.ExitOnError)
	globalFlags.Usage = func() { printUsage(globalFlags) }
	logLevel := globalFlags.String("log-level", "info", "Log level (debug, info, warn, error)")
	logFormat := globalFlags.String("log-format", "console", "Log format (console, json)")

	// Parse global flags from the beginning of the arguments.
	// The flag package stops parsing at the first non-flag argument.
	// Use ContinueOnError to prevent exit on error, so we can show custom help.
	if err := globalFlags.Parse(os.Args[1:]); err == flag.ErrHelp {
		// The flag package's default help was printed. We can exit now.
		os.Exit(0)
	}

	// Initialize logger right after parsing global flags.
	logging.InitLogger(*logLevel, *logFormat, nil)

	// The remaining arguments are the subcommand and its own flags.
	args := globalFlags.Args()
	if len(args) == 0 {
		logging.GetLogger().Error("expected 'proxy', 'test', or 'encrypt-config' subcommands")
		printUsage(globalFlags)
		os.Exit(1)
	}

	command := args[0]
	commandArgs := args[1:]

	switch command {
	case "proxy":
		proxyCmd := flag.NewFlagSet("proxy", flag.ExitOnError)
		addr := proxyCmd.String("addr", "", "proxy listen address (e.g., 127.0.0.1:1080). If empty, uses config or a random port.")
		strategyID := proxyCmd.String("strategy", "", "Specific strategy ID to use. If not provided, the best ranked strategy will be used.")
		configFile := proxyCmd.String("config", "strategies.yaml", "Path to the strategies YAML file.")
		proxyCmd.Usage = func() {
			_, _ = fmt.Fprintf(proxyCmd.Output(), "Usage: gocircum-cli proxy [options]\n\n")
			_, _ = fmt.Fprintf(proxyCmd.Output(), "Runs the SOCKS5 proxy.\n\nOptions:\n")
			proxyCmd.PrintDefaults()
		}
		if err := proxyCmd.Parse(commandArgs); err != nil {
			os.Exit(1) // ExitOnError should have already handled this.
		}
		runProxy(*addr, *strategyID, *configFile)

	case "test":
		testCmd := flag.NewFlagSet("test", flag.ExitOnError)
		configFile := testCmd.String("config", "strategies.yaml", "Path to the strategies YAML file.")
		testCmd.Usage = func() {
			_, _ = fmt.Fprintf(testCmd.Output(), "Usage: gocircum-cli test [options]\n\n")
			_, _ = fmt.Fprintf(testCmd.Output(), "Tests the configured strategies.\n\nOptions:\n")
			testCmd.PrintDefaults()
		}
		if err := testCmd.Parse(commandArgs); err != nil {
			os.Exit(1) // ExitOnError should have already handled this.
		}
		runTest(*configFile)

	case "encrypt-config":
		encryptCmd := flag.NewFlagSet("encrypt-config", flag.ExitOnError)
		encryptCmd.Usage = func() {
			_, _ = fmt.Fprintf(encryptCmd.Output(), "Usage: gocircum-cli encrypt-config [input_file] [output_file]\n\n")
			_, _ = fmt.Fprintf(encryptCmd.Output(), "Encrypts a configuration file using a password.\n\nOptions:\n")
			encryptCmd.PrintDefaults()
		}
		if err := encryptCmd.Parse(commandArgs); err != nil {
			os.Exit(1)
		}

		encryptArgs := encryptCmd.Args()
		if len(encryptArgs) != 2 {
			logging.GetLogger().Error("Expected input and output file paths")
			encryptCmd.Usage()
			os.Exit(1)
		}

		runEncryptConfig(encryptArgs[0], encryptArgs[1])

	default:
		logging.GetLogger().Error("unknown command", "command", command)
		printUsage(globalFlags)
		os.Exit(1)
	}
}

func runProxy(addr, strategyID, configFile string) {
	logger := logging.GetLogger().With("component", "proxy-runner")

	// Check if this is an encrypted config file
	isEncrypted := strings.HasSuffix(configFile, ".enc.yaml")

	var cfg *config.FileConfig
	var err error

	if isEncrypted {
		// Prompt for password
		fmt.Print("Enter config password: ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			logger.Error("Failed to read password", "error", err)
			os.Exit(1)
		}
		fmt.Println()

		// Load encrypted config
		cfg, err = config.LoadSecureConfig(configFile, password)
		if err != nil {
			logger.Error("Failed to load encrypted config", "error", err)
			os.Exit(1)
		}
	} else {
		// Load plaintext config
		cfg, err = config.LoadFileConfig(configFile)
		if err != nil {
			logger.Error("Failed to load config", "error", err)
			os.Exit(1)
		}
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

	// Check if this is an encrypted config file
	isEncrypted := strings.HasSuffix(configFile, ".enc.yaml")

	var cfg *config.FileConfig
	var err error

	if isEncrypted {
		// Prompt for password
		fmt.Print("Enter config password: ")
		password, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			logger.Error("Failed to read password", "error", err)
			os.Exit(1)
		}
		fmt.Println()

		// Load encrypted config
		cfg, err = config.LoadSecureConfig(configFile, password)
		if err != nil {
			logger.Error("Failed to load encrypted config", "error", err)
			os.Exit(1)
		}
	} else {
		// Load plaintext config
		cfg, err = config.LoadFileConfig(configFile)
		if err != nil {
			logger.Error("Failed to load config", "error", err)
			os.Exit(1)
		}
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
	_, _ = fmt.Fprintln(w, "ID\tSUCCESS\tLATENCY\tDESCRIPTION")
	for _, res := range results {
		status := "FAIL"
		if res.Success {
			status = "OK"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", res.Fingerprint.ID, status, res.Latency, res.Fingerprint.Description)
	}
	_ = w.Flush()
}

func runEncryptConfig(inputFile, outputFile string) {
	logger := logging.GetLogger().With("component", "encrypt-config")

	// Check if input file exists
	if _, err := os.Stat(inputFile); os.IsNotExist(err) {
		logger.Error("Input file does not exist", "file", inputFile)
		os.Exit(1)
	}

	// Check if output file already exists
	if _, err := os.Stat(outputFile); err == nil {
		fmt.Printf("Warning: Output file '%s' already exists. Overwrite? (y/n): ", outputFile)
		var answer string
		if _, err := fmt.Scanln(&answer); err != nil {
			fmt.Println("Error reading input:", err)
			return
		}
		if answer != "y" && answer != "Y" {
			logger.Info("Operation cancelled by user")
			os.Exit(0)
		}
	}

	// Prompt for password
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read password", "error", err)
		os.Exit(1)
	}
	fmt.Println()

	// Confirm password
	fmt.Print("Confirm password: ")
	confirmPassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		logger.Error("Failed to read password confirmation", "error", err)
		os.Exit(1)
	}
	fmt.Println()

	// Check if passwords match
	if string(password) != string(confirmPassword) {
		logger.Error("Passwords do not match")
		os.Exit(1)
	}

	// Load the input configuration
	cfg, err := config.LoadFileConfig(inputFile)
	if err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Encrypt the configuration
	err = config.EncryptConfig(cfg, password, outputFile)
	if err != nil {
		logger.Error("Failed to encrypt configuration", "error", err)
		os.Exit(1)
	}

	logger.Info("Configuration encrypted and saved", "output", outputFile)
	fmt.Println("IMPORTANT: Store this password securely. If lost, the configuration cannot be recovered.")
}

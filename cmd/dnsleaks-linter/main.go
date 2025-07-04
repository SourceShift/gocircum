package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gocircum/gocircum/pkg/linter/dnsleaks"
)

var (
	rootDir        = flag.String("dir", ".", "Root directory to scan")
	outputFormat   = flag.String("format", "text", "Output format (text, json)")
	exemptFile     = flag.String("exempt-file", "", "Path to a JSON file containing exemptions")
	strictMode     = flag.Bool("strict", false, "Enforce exemption expiry dates")
	silentMode     = flag.Bool("silent", false, "Only output if issues are found")
	configFile     = flag.String("config", "", "Path to configuration file")
	exitWithCode   = flag.Bool("exit-code", true, "Exit with non-zero code if issues found")
	printExemption = flag.Bool("print-exemption-template", false, "Print a template for exemption file and exit")
)

func main() {
	flag.Parse()

	// Print exemption template if requested
	if *printExemption {
		printExemptionTemplate()
		return
	}

	var config *dnsleaks.Config

	// Load config from file if specified
	if *configFile != "" {
		var err error
		config, err = loadConfigFromFile(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		}
	}

	// If no config loaded, create default
	if config == nil {
		config = dnsleaks.NewDefaultConfig()
	}

	// Override config with exempt file if specified
	if *exemptFile != "" {
		exemptions, err := loadExemptionsFromFile(*exemptFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error loading exemptions: %v\n", err)
		} else {
			config.ExemptFiles = exemptions
		}
	}

	// Set strict mode from command line
	config.StrictMode = *strictMode

	// Resolve absolute path for root directory
	absRootDir, err := filepath.Abs(*rootDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error resolving path: %v\n", err)
		os.Exit(1)
	}

	if !*silentMode {
		fmt.Printf("Scanning directory: %s\n", absRootDir)
	}

	// Run the linter
	issues, err := dnsleaks.LintProject(absRootDir, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during linting: %v\n", err)
		os.Exit(1)
	}

	if len(issues) > 0 {
		switch *outputFormat {
		case "json":
			outputJSON(issues)
		default:
			outputText(issues)
		}

		if *exitWithCode {
			os.Exit(1)
		}
	} else {
		if !*silentMode {
			fmt.Println("No issues found.")
		}
	}
}

func outputText(issues []dnsleaks.Issue) {
	fmt.Printf("Found %d issues:\n\n", len(issues))
	for i, issue := range issues {
		relativePath, err := filepath.Rel(".", issue.File)
		if err != nil {
			relativePath = issue.File
		}
		fmt.Printf("%d) %s:%d:%d: %s\n", i+1, relativePath, issue.Line, issue.Column, issue.Message)
	}
	fmt.Println("\nDNS resolution must use securedns.Resolver to prevent DNS leaks.")
	fmt.Println("See https://github.com/gocircum/gocircum/blob/main/pkg/securedns/README.md for details.")
}

func outputJSON(issues []dnsleaks.Issue) {
	type jsonOutput struct {
		Issues      []dnsleaks.Issue `json:"issues"`
		TotalIssues int              `json:"total_issues"`
		Summary     string           `json:"summary"`
	}

	output := jsonOutput{
		Issues:      issues,
		TotalIssues: len(issues),
		Summary:     "DNS leaks detected in codebase",
	}

	jsonData, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling to JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}

func loadExemptionsFromFile(filePath string) ([]dnsleaks.ExemptFile, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var exemptions []dnsleaks.ExemptFile
	err = json.Unmarshal(data, &exemptions)
	if err != nil {
		return nil, err
	}

	return exemptions, nil
}

func loadConfigFromFile(filePath string) (*dnsleaks.Config, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var config dnsleaks.Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func printExemptionTemplate() {
	exemptions := []dnsleaks.ExemptFile{
		{
			Path:   "path/to/exempt/file.go",
			Reason: "Reason for exemption",
		},
		{
			Path:       "another/path/file.go",
			Reason:     "Another reason for exemption",
			ExpiryDate: "2023-12-31",
		},
	}

	jsonData, err := json.MarshalIndent(exemptions, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating template: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}

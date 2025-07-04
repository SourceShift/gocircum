package mathrandom

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// Issue represents a detected usage of math/rand
type Issue struct {
	File    string
	Line    int
	Column  int
	Message string
}

// ExemptFile contains information about a file exempt from math/rand checks
type ExemptFile struct {
	Path       string
	Reason     string
	ExpiryDate string // Optional: YYYY-MM-DD format to indicate when the exemption expires
}

// Config contains configuration for the linter
type Config struct {
	// ExemptFiles is a list of files exempt from math/rand checks
	ExemptFiles []ExemptFile

	// ExemptDirectories is a list of directories exempt from math/rand checks
	ExemptDirectories []string

	// LogExemptions determines whether to log when an exemption is used
	LogExemptions bool

	// StrictMode fails on exemptions that have expired
	StrictMode bool
}

// NewDefaultConfig creates a default configuration
func NewDefaultConfig() *Config {
	return &Config{
		ExemptFiles:       []ExemptFile{},
		ExemptDirectories: []string{},
		LogExemptions:     false,
		StrictMode:        true,
	}
}

// LintProject checks all Go files in a project for math/rand imports
func LintProject(rootDir string, config *Config) ([]Issue, error) {
	if config == nil {
		config = NewDefaultConfig()
	}

	var issues []Issue

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			// Check if directory is exempt
			for _, exemptDir := range config.ExemptDirectories {
				exemptPath := filepath.Join(rootDir, exemptDir)
				if strings.HasPrefix(path, exemptPath) {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Only process Go files
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		// Check if file is exempt
		for _, exemptFile := range config.ExemptFiles {
			if strings.HasSuffix(path, exemptFile.Path) {
				if config.LogExemptions {
					fmt.Printf("Skipping exempt file: %s (Reason: %s)\n", path, exemptFile.Reason)
				}
				return nil
			}
		}

		fileIssues, err := LintFile(path)
		if err != nil {
			return fmt.Errorf("error linting file %s: %w", path, err)
		}

		issues = append(issues, fileIssues...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("error walking directory: %w", err)
	}

	return issues, nil
}

// LintFile checks a single Go file for math/rand imports
func LintFile(filePath string) ([]Issue, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("error parsing file: %w", err)
	}

	var issues []Issue

	// Check imports
	for _, imp := range node.Imports {
		importPath := strings.Trim(imp.Path.Value, "\"")
		if importPath == "math/rand" {
			pos := fset.Position(imp.Pos())
			issues = append(issues, Issue{
				File:    filePath,
				Line:    pos.Line,
				Column:  pos.Column,
				Message: "math/rand package is prohibited. Use pkg/securerandom instead.",
			})
		}

		if strings.HasPrefix(importPath, "math/rand/") {
			pos := fset.Position(imp.Pos())
			issues = append(issues, Issue{
				File:    filePath,
				Line:    pos.Line,
				Column:  pos.Column,
				Message: "math/rand subpackage is prohibited. Use pkg/securerandom instead.",
			})
		}
	}

	// Check for aliased imports of math/rand
	for _, imp := range node.Imports {
		if imp.Name != nil {
			importPath := strings.Trim(imp.Path.Value, "\"")
			if importPath == "math/rand" {
				pos := fset.Position(imp.Pos())
				issues = append(issues, Issue{
					File:    filePath,
					Line:    pos.Line,
					Column:  pos.Column,
					Message: fmt.Sprintf("Aliased import of math/rand as '%s' is prohibited. Use pkg/securerandom instead.", imp.Name.Name),
				})
			}
		}
	}

	// Check for dot imports which are especially dangerous for math/rand
	for _, imp := range node.Imports {
		if imp.Name != nil && imp.Name.Name == "." {
			importPath := strings.Trim(imp.Path.Value, "\"")
			if importPath == "math/rand" {
				pos := fset.Position(imp.Pos())
				issues = append(issues, Issue{
					File:    filePath,
					Line:    pos.Line,
					Column:  pos.Column,
					Message: "Dot import of math/rand is strictly prohibited as it makes insecure functions available in the global namespace.",
				})
			}
		}
	}

	return issues, nil
}

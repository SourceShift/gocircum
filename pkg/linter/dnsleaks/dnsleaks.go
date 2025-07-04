package dnsleaks

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// Issue represents a detected insecure DNS resolution API usage
type Issue struct {
	File    string
	Line    int
	Column  int
	Message string
}

// ExemptFile contains information about a file exempt from DNS leak checks
type ExemptFile struct {
	Path       string
	Reason     string
	ExpiryDate string // Optional: YYYY-MM-DD format to indicate when the exemption expires
}

// Config contains configuration for the linter
type Config struct {
	// ExemptFiles is a list of files exempt from DNS leak checks
	ExemptFiles []ExemptFile

	// ExemptDirectories is a list of directories exempt from DNS leak checks
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
		LogExemptions:     true,
		StrictMode:        false,
	}
}

// LintProject checks all Go files in a project for insecure DNS usage
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
			// Skip exempt directories
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

		// Skip exempt files
		for _, exemptFile := range config.ExemptFiles {
			if strings.HasSuffix(path, exemptFile.Path) {
				if config.LogExemptions {
					fmt.Printf("Skipping exempt file: %s (Reason: %s)\n", path, exemptFile.Reason)
				}
				return nil
			}
		}

		// Check the file for insecure DNS usage
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

// LintFile checks a single Go file for insecure DNS usage
func LintFile(filePath string) ([]Issue, error) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		return nil, fmt.Errorf("error parsing file: %w", err)
	}

	var issues []Issue
	imports := make(map[string]string)

	// First pass: collect imports to detect aliasing
	for _, imp := range node.Imports {
		importPath := strings.Trim(imp.Path.Value, "\"")

		// Handle aliased imports
		var importName string
		if imp.Name != nil {
			importName = imp.Name.Name
		} else {
			// Extract the last part of the import path as the default name
			parts := strings.Split(importPath, "/")
			importName = parts[len(parts)-1]
		}

		imports[importName] = importPath
	}

	// Process all function calls in the file
	ast.Inspect(node, func(n ast.Node) bool {
		// Check for net.LookupIP calls
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.Ident); ok {
					// Check direct imports of net package
					if x.Name == "net" && isUnsafeDNSMethod(sel.Sel.Name) {
						pos := fset.Position(sel.Pos())
						issues = append(issues, Issue{
							File:    filePath,
							Line:    pos.Line,
							Column:  pos.Column,
							Message: fmt.Sprintf("Direct use of net.%s is prohibited. Use securedns.Resolver instead.", sel.Sel.Name),
						})
					}

					// Check aliased imports
					if importPath, ok := imports[x.Name]; ok && importPath == "net" {
						if isUnsafeDNSMethod(sel.Sel.Name) {
							pos := fset.Position(sel.Pos())
							issues = append(issues, Issue{
								File:    filePath,
								Line:    pos.Line,
								Column:  pos.Column,
								Message: fmt.Sprintf("Aliased import use of net.%s is prohibited. Use securedns.Resolver instead.", sel.Sel.Name),
							})
						}
					}
				}
			}
		}

		// Check for net.DefaultResolver references
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok {
				if x.Name == "net" && sel.Sel.Name == "DefaultResolver" {
					pos := fset.Position(sel.Pos())
					issues = append(issues, Issue{
						File:    filePath,
						Line:    pos.Line,
						Column:  pos.Column,
						Message: "Direct use of net.DefaultResolver is prohibited. Use securedns.Resolver instead.",
					})
				}

				// Check aliased imports
				if importPath, ok := imports[x.Name]; ok && importPath == "net" {
					if sel.Sel.Name == "DefaultResolver" {
						pos := fset.Position(sel.Pos())
						issues = append(issues, Issue{
							File:    filePath,
							Line:    pos.Line,
							Column:  pos.Column,
							Message: "Aliased import use of net.DefaultResolver is prohibited. Use securedns.Resolver instead.",
						})
					}
				}
			}
		}

		// Check for insecure net.Dialer instantiation
		if call, ok := n.(*ast.CompositeLit); ok {
			if typ, ok := call.Type.(*ast.SelectorExpr); ok {
				if x, ok := typ.X.(*ast.Ident); ok {
					if x.Name == "net" && typ.Sel.Name == "Dialer" {
						pos := fset.Position(typ.Pos())
						issues = append(issues, Issue{
							File:    filePath,
							Line:    pos.Line,
							Column:  pos.Column,
							Message: "Creating net.Dialer directly is potentially insecure. Use securedns.SecureDialerFactory instead.",
						})
					}

					// Check aliased imports
					if importPath, ok := imports[x.Name]; ok && importPath == "net" {
						if typ.Sel.Name == "Dialer" {
							pos := fset.Position(typ.Pos())
							issues = append(issues, Issue{
								File:    filePath,
								Line:    pos.Line,
								Column:  pos.Column,
								Message: "Creating net.Dialer through aliased import is potentially insecure. Use securedns.SecureDialerFactory instead.",
							})
						}
					}
				}
			}
		}

		// Check for net.Resolver instantiation
		if call, ok := n.(*ast.CompositeLit); ok {
			if typ, ok := call.Type.(*ast.SelectorExpr); ok {
				if x, ok := typ.X.(*ast.Ident); ok {
					if x.Name == "net" && typ.Sel.Name == "Resolver" {
						pos := fset.Position(typ.Pos())
						issues = append(issues, Issue{
							File:    filePath,
							Line:    pos.Line,
							Column:  pos.Column,
							Message: "Creating net.Resolver directly is insecure. Use securedns.Resolver instead.",
						})
					}

					// Check aliased imports
					if importPath, ok := imports[x.Name]; ok && importPath == "net" {
						if typ.Sel.Name == "Resolver" {
							pos := fset.Position(typ.Pos())
							issues = append(issues, Issue{
								File:    filePath,
								Line:    pos.Line,
								Column:  pos.Column,
								Message: "Creating net.Resolver through aliased import is insecure. Use securedns.Resolver instead.",
							})
						}
					}
				}
			}
		}

		// Check for direct use of system DNS resolution functions
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if x, ok := sel.X.(*ast.SelectorExpr); ok {
					if pkg, ok := x.X.(*ast.Ident); ok {
						if pkg.Name == "net" && x.Sel.Name == "DefaultResolver" && isUnsafeDNSMethod(sel.Sel.Name) {
							pos := fset.Position(sel.Pos())
							issues = append(issues, Issue{
								File:    filePath,
								Line:    pos.Line,
								Column:  pos.Column,
								Message: fmt.Sprintf("Use of net.DefaultResolver.%s is prohibited. Use securedns.Resolver instead.", sel.Sel.Name),
							})
						}

						// Check aliased imports of DefaultResolver
						if importPath, ok := imports[pkg.Name]; ok && importPath == "net" {
							if x.Sel.Name == "DefaultResolver" && isUnsafeDNSMethod(sel.Sel.Name) {
								pos := fset.Position(sel.Pos())
								issues = append(issues, Issue{
									File:    filePath,
									Line:    pos.Line,
									Column:  pos.Column,
									Message: fmt.Sprintf("Use of aliased net.DefaultResolver.%s is prohibited. Use securedns.Resolver instead.", sel.Sel.Name),
								})
							}
						}
					}
				}
			}
		}

		return true
	})

	return issues, nil
}

// isUnsafeDNSMethod checks if a method name is a known unsafe DNS resolution method
func isUnsafeDNSMethod(methodName string) bool {
	unsafeMethods := map[string]bool{
		"LookupIP":     true,
		"LookupIPAddr": true,
		"LookupHost":   true,
		"LookupAddr":   true,
		"LookupCNAME":  true,
		"LookupMX":     true,
		"LookupNS":     true,
		"LookupSRV":    true,
		"LookupTXT":    true,
		"Dial":         true,
		"DialContext":  true,
	}

	return unsafeMethods[methodName]
}

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod
GOMOBILE=gomobile
GOLINT=golangci-lint

# Project paths
CLI_DIR=./cli
MOBILE_PKG=./mobile
BUILD_DIR=./build
BIN_DIR=./bin
CLI_OUTPUT=$(BIN_DIR)/gocircum-cli

# Default target runs the build for all artifacts
.PHONY: all
all: build-cli build-mobile

# Help target to display available commands
.PHONY: help
help:
	@echo "Available commands:"
	@echo "  build            Build the project"
	@echo "  clean            Clean build artifacts"
	@echo "  deps             Install dependencies"
	@echo "  help             Show this help message"
	@echo "  install-deps     Install required tools"
	@echo "  lint             Lint the codebase with golangci-lint"
	@echo "  lint-mathrandom  Check for insecure math/rand usage"
	@echo "  lint-dnsleaks    Check for DNS leaks"
	@echo "  lint-all         Run all linters (golangci-lint, mathrandom, and dnsleaks)"
	@echo "  tidy             Tidy go.mod and go.sum files"
	@echo "  test             Run tests"
	@echo "  test-race        Run tests with race detector"
	@echo "  test-all         Run all tests including integration tests"
	@echo "  coverage         Generate test coverage report"

# Dependency installation
.PHONY: install-deps
install-deps:
	@echo "Installing gomobile and golangci-lint..."
	$(GOCMD) install golang.org/x/mobile/cmd/gomobile@latest
	$(GOMOBILE) init
	$(GOCMD) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

# Build targets
.PHONY: build-cli
build-cli:
	@echo "Building gocircum-cli..."
	@mkdir -p $(BIN_DIR)
	$(GOBUILD) -o $(CLI_OUTPUT) $(CLI_DIR)

.PHONY: build-mobile
build-mobile: android ios
	@echo "Mobile libraries built successfully in $(BUILD_DIR)"

.PHONY: android
android:
	@echo "Building Android library (.aar)..."
	@mkdir -p $(BUILD_DIR)/android
	$(GOMOBILE) bind -o $(BUILD_DIR)/android/gocircum.aar -target=android $(MOBILE_PKG)

.PHONY: ios
ios:
	@echo "Building iOS framework (.xcframework)..."
	@mkdir -p $(BUILD_DIR)/ios
	$(GOMOBILE) bind -o $(BUILD_DIR)/ios/Gocircum.xcframework -target=ios $(MOBILE_PKG)

# Testing and linting
.PHONY: test
test:
	@echo "Running tests for standard packages..."
	$(eval PKGS_TO_TEST := $(shell go list ./... | grep -v /mobile))
	@echo "Running tests on packages: $(PKGS_TO_TEST)"
	$(GOTEST) -timeout 30s -v -count=1 $(PKGS_TO_TEST)
	@echo "Running mobile bridge tests specifically..."
	$(GOTEST) -timeout 10s -v -count=1 ./mobile/bridge

.PHONY: test-race
test-race:
	@echo "Running tests with race detector..."
	$(eval PKGS_TO_TEST := $(shell go list ./... | grep -v /mobile))
	@echo "Running tests on packages: $(PKGS_TO_TEST)"
	$(GOTEST) -timeout 60s -v -race -count=1 $(PKGS_TO_TEST)
	@echo "Running mobile bridge tests specifically with race detector..."
	$(GOTEST) -timeout 30s -v -race -count=1 ./mobile/bridge

.PHONY: lint
lint:
	@echo "Linting code..."
	@command -v $(GOLINT) >/dev/null 2>&1 || { echo >&2 "golangci-lint not found. Please run 'make install-deps'"; exit 1; }
	$(GOLINT) run ./...

.PHONY: lint-mathrandom
lint-mathrandom:
	@echo "Checking for insecure math/rand usage..."
	@mkdir -p $(BIN_DIR)
	@if [ ! -f "$(BIN_DIR)/mathrandom-linter" ]; then \
		echo "Building mathrandom-linter..."; \
		$(GOBUILD) -o $(BIN_DIR)/mathrandom-linter ./cmd/mathrandom-linter; \
	fi
	$(BIN_DIR)/mathrandom-linter -dir=. -exempt-file=./configs/mathrandom-exempt.json

.PHONY: lint-dnsleaks
lint-dnsleaks:
	@echo "Checking for DNS leaks..."
	@mkdir -p $(BIN_DIR)
	@if [ ! -f "$(BIN_DIR)/dnsleaks-linter" ]; then \
		echo "Building dnsleaks-linter..."; \
		$(GOBUILD) -o $(BIN_DIR)/dnsleaks-linter ./cmd/dnsleaks-linter; \
	fi
	$(BIN_DIR)/dnsleaks-linter -dir=. -exempt-file=./configs/dnsleaks-exempt.json

.PHONY: lint-all
lint-all: lint lint-mathrandom lint-dnsleaks
	@echo "All linting checks completed"

# Dependency management
.PHONY: tidy
tidy:
	@echo "Tidying go modules..."
	$(GOMOD) tidy

# Clean up
.PHONY: clean
clean:
	@echo "Cleaning up build artifacts..."
	rm -rf $(BIN_DIR) $(BUILD_DIR)

.PHONY: repomix
repomix:
	@echo "Running repomix with ignore patterns..."
	repomix --ignore '**/*mock**,**/*test*,**/*.json,**/*.js,**/*.md,**/*.svg,**/*.xml,./onepager/**,**/*.py,**/*.txt,**/docs,**/LICENSE' 
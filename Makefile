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
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  all              Build all artifacts (CLI and mobile libraries)"
	@echo "  install-deps     Install Go mobile and linter dependencies"
	@echo "  build-cli        Build the gocircum-cli application"
	@echo "  build-mobile     Build mobile libraries for iOS and Android"
	@echo "  android          Build the Android .aar library"
	@echo "  ios              Build the iOS .xcframework"
	@echo "  test             Run all Go tests"
	@echo "  test-race        Run all Go tests with the race detector"
	@echo "  lint             Lint the codebase with golangci-lint"
	@echo "  tidy             Tidy go.mod and go.sum files"
	@echo "  clean            Remove all build artifacts"
	@echo "  help             Show this help message"

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
	repomix --ignore '**/*mock**,**/*test*,**/*.json,**/*.js,**/*.md,**/*.svg,**/*.xml,./onepager/**,**/*.py,**/*.txt,**/docs,**/LICENSE,**/Makefile' 
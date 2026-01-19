.PHONY: build install clean test lint fmt deps run help

# Binary name
BINARY_NAME=sentinel
VERSION?=0.1.0
BUILD_DIR=./bin
GO=go

# Get git commit and build date
GIT_COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.gitCommit=$(GIT_COMMIT) -X main.buildDate=$(BUILD_DATE) -s -w"

# Default target
all: deps build

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/sentinel

## build-all: Build for multiple platforms
build-all:
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ./cmd/sentinel
	GOOS=linux GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ./cmd/sentinel
	GOOS=darwin GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ./cmd/sentinel
	GOOS=darwin GOARCH=arm64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ./cmd/sentinel
	GOOS=windows GOARCH=amd64 $(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ./cmd/sentinel

## install: Install the binary to /usr/local/bin
install: build
	@echo "Installing $(BINARY_NAME)..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	@echo "Installed to /usr/local/bin/$(BINARY_NAME)"

## uninstall: Remove the installed binary
uninstall:
	@echo "Uninstalling $(BINARY_NAME)..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

## deps: Download dependencies
deps:
	@echo "Downloading dependencies..."
	$(GO) mod download
	$(GO) mod tidy

## test: Run tests
test:
	@echo "Running tests..."
	$(GO) test -v -race -cover ./...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "Running tests with coverage..."
	$(GO) test -v -race -coverprofile=coverage.out ./...
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## lint: Run linter
lint:
	@echo "Running linter..."
	golangci-lint run ./...

## fmt: Format code
fmt:
	@echo "Formatting code..."
	$(GO) fmt ./...
	goimports -w .

## vet: Run go vet
vet:
	@echo "Running go vet..."
	$(GO) vet ./...

## clean: Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

## run: Run the application
run: build
	$(BUILD_DIR)/$(BINARY_NAME)

## run-validate: Run validation example
run-validate: build
	$(BUILD_DIR)/$(BINARY_NAME) validate -- run --privileged nginx

## run-scan: Run scan example
run-scan: build
	$(BUILD_DIR)/$(BINARY_NAME) scan nginx:latest

## docker-build: Build Docker image
docker-build:
	docker build -t docker-sentinel:$(VERSION) .

## init-config: Initialize default configuration
init-config:
	@echo "Initializing configuration..."
	mkdir -p ~/.sentinel/policies
	cp configs/policies/default.yaml ~/.sentinel/policies/
	@echo "Configuration initialized at ~/.sentinel/"

## help: Show this help message
help:
	@echo "Docker Sentinel - Pre-runtime Container Security"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'

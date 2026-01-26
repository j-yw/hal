# GoRalph Makefile

BINARY_NAME := goralph
INSTALL_PATH := ~/.local/bin
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X github.com/jywlabs/goralph/cmd.Version=$(VERSION) -X github.com/jywlabs/goralph/cmd.Commit=$(COMMIT) -X github.com/jywlabs/goralph/cmd.BuildDate=$(BUILD_DATE)"

.PHONY: all build install uninstall clean test vet fmt lint run help

## Default target
all: build

## Build the binary
build:
	@echo "==> Building $(BINARY_NAME)..."
	@go build $(LDFLAGS) -o $(BINARY_NAME) .
	@echo "    Built ./$(BINARY_NAME)"

## Install to ~/.local/bin
install: build
	@echo "==> Installing to $(INSTALL_PATH)/$(BINARY_NAME)..."
	@mkdir -p $(INSTALL_PATH)
	@cp $(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "    Installed $(INSTALL_PATH)/$(BINARY_NAME)"

## Uninstall from ~/.local/bin
uninstall:
	@echo "==> Removing $(INSTALL_PATH)/$(BINARY_NAME)..."
	@rm -f $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "    Removed"

## Clean build artifacts
clean:
	@echo "==> Cleaning..."
	@rm -f $(BINARY_NAME)
	@go clean
	@echo "    Clean"

## Run tests
test:
	@echo "==> Running tests..."
	@go test -v ./...

## Run go vet
vet:
	@echo "==> Running go vet..."
	@go vet ./...

## Format code
fmt:
	@echo "==> Formatting code..."
	@go fmt ./...

## Run linter (requires golangci-lint)
lint:
	@echo "==> Running linter..."
	@golangci-lint run ./... || echo "    Install: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"

## Run goralph (for quick testing)
run: build
	@./$(BINARY_NAME) $(ARGS)

## Show version info
version: build
	@./$(BINARY_NAME) version

## Show help
help:
	@echo "GoRalph Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build      Build the binary"
	@echo "  make install    Install to ~/.local/bin"
	@echo "  make uninstall  Remove from ~/.local/bin"
	@echo "  make clean      Remove build artifacts"
	@echo "  make test       Run tests"
	@echo "  make vet        Run go vet"
	@echo "  make fmt        Format code"
	@echo "  make lint       Run golangci-lint"
	@echo "  make run        Build and run (use ARGS=... for args)"
	@echo "  make version    Show version info"
	@echo ""
	@echo "Examples:"
	@echo "  make install"
	@echo "  make run ARGS='--help'"
	@echo "  make run ARGS='run --max 5'"

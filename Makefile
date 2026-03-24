BINARY := jawt
MAIN := ./cmd/jawt
BUILD_DIR := bin

GO := go

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -ldflags "-s -w \
-X main.version=$(VERSION) \
-X main.commit=$(COMMIT) \
-X main.date=$(DATE)"

GREEN  := \033[0;32m
YELLOW := \033[0;33m
RESET  := \033[0m

.DEFAULT_GOAL := help

.PHONY: help build run test lint vulncheck fmt vet clean install tools

help: ## Show available targets
	@echo ""
	@echo -e "$(GREEN)Available targets:$(RESET)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "  $(YELLOW)%-15s$(RESET) %s\n", $$1, $$2}'
	@echo ""

check: clean fmt lint test vet vulncheck build ## Run all checks

build: ## Build the CLI binary
	@echo -e "$(GREEN)Building $(BINARY) $(VERSION)$(RESET)"
	@mkdir -p $(BUILD_DIR)
	$(GO) build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) $(MAIN)

run: ## Run the CLI
	$(GO) run $(LDFLAGS) $(MAIN)

test: ## Run tests
	$(GO) test -v ./...

lint: ## Run linter
	golangci-lint run

fmt: ## Format code
	$(GO) fmt ./...

vet: ## Run go vet
	$(GO) vet ./...

vulncheck: ## Run govulncheck
	govulncheck ./...

clean: ## Remove build artifacts
	@echo -e "$(GREEN)Cleaning$(RESET)"
	rm -rf $(BUILD_DIR)

install: fmt lint test vet vulncheck ## Install CLI in $GOPATH/bin
	$(GO) install $(LDFLAGS) $(MAIN)

tools: ## Install development tools
	$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
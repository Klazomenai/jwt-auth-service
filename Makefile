.PHONY: test test-verbose clean build help docker-build docker-push

# Default target
.DEFAULT_GOAL := test

# Go parameters
GOCMD=go
GOTEST=$(GOCMD) test
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOMOD=$(GOCMD) mod

# Docker parameters
DOCKER_REGISTRY ?= ghcr.io/klazomenai
IMAGE_NAME ?= jwt-auth-service
IMAGE_TAG ?= latest
FULL_IMAGE = $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

help: ## Display this help message
	@echo "Available targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

test: ## Run all Go unit tests
	@echo "Running Go unit tests..."
	$(GOTEST) -v ./...

test-verbose: ## Run tests with verbose output and coverage
	@echo "Running Go tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...
	@echo ""
	@echo "Coverage summary:"
	$(GOCMD) tool cover -func=coverage.out | grep total

test-coverage: ## Run tests and generate HTML coverage report
	@echo "Running Go tests with coverage..."
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

build: ## Build the JWT token service binary
	@echo "Building JWT token service..."
	$(GOBUILD) -o bin/jwt-service ./cmd/server

clean: ## Clean build artifacts and test cache
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -f coverage.out coverage.html
	rm -rf bin/

deps: ## Download Go module dependencies
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

fmt: ## Format Go code
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

vet: ## Run go vet
	@echo "Running go vet..."
	$(GOCMD) vet ./...

lint: fmt vet ## Run formatters and linters
	@echo "Linting complete"

all: clean deps lint test build ## Run all checks and build
	@echo "All tasks completed successfully"

docker-build: ## Build Docker image
	@echo "Building Docker image: $(FULL_IMAGE)"
	docker build -t $(FULL_IMAGE) .
	@echo "Build complete: $(FULL_IMAGE)"

docker-push: docker-build ## Push Docker image to registry
	@echo "Pushing Docker image: $(FULL_IMAGE)"
	docker push $(FULL_IMAGE)

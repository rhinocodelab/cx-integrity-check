# Makefile for building the file-encryptor CLI

# Binary name
BINARY_NAME = file-encryptor

# Default GOOS and GOARCH (can be overridden)
GOOS ?= linux
GOARCH ?= amd64

# Source files
SOURCES = *.go

# Build flags for static linking
LDFLAGS = -ldflags "-w -s -extldflags '-static'"

# Default target
all: build

# Build the static binary
build:
	@echo "Building static binary for $(GOOS)/$(GOARCH)..."
	@CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build $(LDFLAGS) -o $(BINARY_NAME) $(SOURCES)
	@echo "Binary built: $(BINARY_NAME)"

# Cross-compilation targets
build-linux:
	@$(MAKE) build GOOS=linux GOARCH=amd64

build-windows:
	@$(MAKE) build GOOS=windows GOARCH=amd64 BINARY_NAME=$(BINARY_NAME).exe

build-darwin:
	@$(MAKE) build GOOS=darwin GOARCH=amd64

# Clean up build artifacts
clean:
	@echo "Cleaning up..."
	@rm -f $(BINARY_NAME) $(BINARY_NAME).exe
	@echo "Clean complete"

# Show help
help:
	@echo "Makefile for building $(BINARY_NAME)"
	@echo ""
	@echo "Usage:"
	@echo "  make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  all          Build the static binary (default)"
	@echo "  build        Build the static binary for specified GOOS/GOARCH"
	@echo "  build-linux  Build for Linux/amd64"
	@echo "  build-windows Build for Windows/amd64"
	@echo "  build-darwin Build for macOS/amd64"
	@echo "  clean        Remove built binaries"
	@echo "  help         Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  GOOS         Target operating system (default: linux)"
	@echo "  GOARCH       Target architecture (default: amd64)"
	@echo "  BINARY_NAME  Name of the output binary (default: $(BINARY_NAME))"
	@echo ""
	@echo "Examples:"
	@echo "  make build-linux              # Build for Linux"
	@echo "  make build GOOS=linux GOARCH=arm  # Build for Linux ARM"
	@echo "  make clean                    # Remove binaries"

.PHONY: all build build-linux build-windows build-darwin clean help
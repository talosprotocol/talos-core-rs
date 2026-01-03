# talos-core-rs Makefile
# High-performance Rust Kernel

.PHONY: install build test lint clean start stop

# Default target
all: build test

# Install dependencies (cargo handles this)
install:
	@echo "Rust dependencies managed by cargo"

# Build
build:
	@echo "Building..."
	cargo build --release

# Run tests
test:
	@echo "Running tests..."
	cargo test --all-features

# Lint check
lint:
	@echo "Running lint..."
	cargo fmt --check
	cargo clippy -- -D warnings

# Clean all generated files
clean:
	@echo "Cleaning..."
	cargo clean
	rm -rf target
	@echo "Clean complete. Ready for fresh build."

# No services to start for core-rs
start:
	@echo "talos-core-rs is a library, no services to start."

stop:
	@echo "talos-core-rs is a library, no services to stop."

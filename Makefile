# talos-core-rs Makefile

.PHONY: build test conformance clean doctor start stop

# Default target
all: build test

build:
	@echo "Building Rust kernel..."
	cargo build --release

test:
	@echo "Running tests..."
	cargo test

# Mapped to test for now as Rust tests include vector verification if implemented
conformance:
	@echo "Running conformance tests..."
	cargo test

doctor:
	@echo "Checking environment..."
	@cargo --version || echo "Cargo missing"
	@rustc --version || echo "Rustc missing"

clean:
	@echo "Cleaning..."
	cargo clean
	rm -rf target

# Scripts wrapper
start:
	@./scripts/start.sh

stop:
	@./scripts/stop.sh

# Universal Makefile Interface
all: install lint test build conformance

install:
	cargo fetch

typecheck:
	cargo check

lint:
	# Style + Types (Fail on error)
	cargo clippy --all-targets -- -D warnings

format:
	# Auto-fix style
	cargo fmt

test:
	# Unit tests
	cargo test

conformance:
	# Run conformance vectors
	@if [ -z "$(RELEASE_SET)" ]; then \
		echo "Skipping conformance (No RELEASE_SET provided)"; \
	else \
		cargo test --test conformance -- --vectors $(RELEASE_SET); \
	fi

build:
	cargo build --release

clean:
	cargo clean

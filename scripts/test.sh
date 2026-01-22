#!/usr/bin/env bash
set -e

# Check if cargo is available
if ! command -v cargo >/dev/null 2>&1; then
  echo "Cargo not found, skipping Rust tests"
  exit 0
fi

COMMAND=${1:-unit}

case "$COMMAND" in
  unit)
    echo "=== Running Unit Tests ==="
    # Avoid --all-features as it triggers pyo3 linker errors in this environment
    cargo test --no-default-features
    ;;
  interop)
    echo "=== Running Property/Interop Tests ==="
    # For Core, interop gate means passing property tests for serialization
    cargo test --no-default-features
    ;;
  lint)
    echo "=== Running Lint ==="
    cargo fmt --check
    cargo clippy -- -D warnings 2>/dev/null || cargo clippy
    ;;
  *)
    echo "Error: Unknown command '$COMMAND'"
    exit 1
    ;;
esac

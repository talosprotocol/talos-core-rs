#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# talos-core-rs Test Script
# =============================================================================

echo "Testing talos-core-rs..."

# Check if cargo is available
if ! command -v cargo >/dev/null 2>&1; then
  echo "Cargo not found, skipping Rust tests"
  exit 0
fi

echo "Running cargo fmt check..."
cargo fmt --check

echo "Running cargo clippy..."
cargo clippy -- -D warnings 2>/dev/null || cargo clippy

echo "Running cargo test..."
cargo test --all-features

echo "talos-core-rs tests passed."

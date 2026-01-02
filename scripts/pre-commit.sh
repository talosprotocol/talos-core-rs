#!/usr/bin/env bash
set -euo pipefail

echo "🔍 Running pre-commit validation..."

# 1. Version bump
# Requires cargo-bump: cargo install cargo-bump
if command -v cargo-bump &> /dev/null; then
    echo "📦 Syncing version..."
    cargo bump patch --no-tag || true
else
    echo "⚠️  cargo-bump not found, skipping version sync"
fi

# 2. Checks
echo "✨ Running cargo fmt..."
cargo fmt --all --check

echo "🛡️  Running cargo clippy..."
cargo clippy --all-targets --all-features -- -D warnings

echo "🧪 Running cargo test..."
cargo test --all-features

# 3. Stage version bump
git add Cargo.toml Cargo.lock || true

echo "✅ All pre-commit checks passed"

#!/usr/bin/env bash
set -euo pipefail

# talos-core-rs cleanup script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Cleaning talos-core-rs..."
cd "$REPO_DIR"

cargo clean 2>/dev/null || true
rm -rf target

echo "✓ talos-core-rs cleaned"

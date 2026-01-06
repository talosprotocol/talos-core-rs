#!/bin/bash
set -euo pipefail

echo "Cleaning talos-core-rs..."
# Rust build artifacts
cargo clean 2>/dev/null || true
rm -rf target 2>/dev/null || true
# Coverage & reports (tarpaulin, grcov, etc.)
rm -f tarpaulin-report.* lcov.info cobertura.xml 2>/dev/null || true
rm -rf coverage 2>/dev/null || true
echo "✓ talos-core-rs cleaned"

#!/bin/bash
set -euo pipefail

echo "Cleaning up..."
cargo clean
rm -rf target

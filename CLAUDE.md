# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is the Talos Core, a high-performance Rust kernel that implements the core protocol logic for the Talos Protocol. It's the performance-critical part of the system, written in Rust for safety and speed. The core module provides the foundational cryptographic primitives and state machine logic for the Talos ecosystem, serving as the reference implementation for core algorithms.

## Repository Structure

Key directories and files in this repository include:

- `src/` - Main Rust source code organized by modules
- `tests/` - Integration and conformance tests
- `examples/` - Example usage of the core functionality
- `scripts/` - Development and CI scripts
- `artifacts/` - Generated artifacts like coverage reports
- `Cargo.toml` - Rust package manifest
- `Makefile` - Standardized build interface

## Common Development Commands

### Setup and Initialization
```bash
# Install Rust dependencies
make install

# Or directly with cargo
cargo fetch
```

### Building
```bash
# Build release version
make build

# Or directly with cargo
cargo build --release

# Check for compilation errors
make typecheck

# Run linter
make lint

# Format code
make format
```

### Testing
```bash
# Run unit tests
make test

# Or directly with cargo
cargo test --no-default-features

# Run tests with the standardized test script
scripts/test.sh --unit

# Run smoke tests
scripts/test.sh --smoke

# Run coverage
make coverage

# Run all tests with coverage
scripts/test.sh --ci
```

### Cleaning
```bash
# Clean build artifacts
make clean

# Or directly with cargo
cargo clean
```

## Architecture Guidelines

1. **Performance Critical**: This is the performance-critical part of the system. Pay attention to optimization and efficiency.

2. **Memory Safety**: Rust's ownership model guarantees memory safety. Avoid unsafe code unless absolutely necessary for FFI boundaries.

3. **Cryptographic Correctness**: This module contains cryptographic primitives. Follow established best practices for cryptographic implementations.

4. **FFI Compatibility**: The core exposes a foreign function interface for other languages to use the Rust implementation.

## Language-Specific Patterns

### Rust (Core)
- Uses `cargo test` for unit tests
- `cargo llvm-cov` or `cargo tarpaulin` for coverage reports
- Tests located in `tests/` directory and inline with source code
- Makefile provides standardized interface (`make test`, `make build`, etc.)

### Key Modules
- **ratchet**: Double Ratchet state machine
- **x3dh**: Extended Triple Diffie-Hellman key agreement
- **crypto**: Wrappers for X25519, Ed25519, ChaCha20-Poly1305

## Key Scripts and Tools

- `scripts/test.sh` - Standardized test entrypoint supporting various test modes
- `Makefile` - Universal interface for common development tasks
- `cargo` - Rust package manager and build tool

## Development Workflow

1. Make changes to Rust source files in `src/`
2. Run `make test` or `scripts/test.sh --unit` to validate
3. Run `make lint` to ensure code quality
4. Run `make build` to ensure build integrity
5. Commit changes (CI will run full test suite)

## Security Considerations

- **Memory Safety**: Guaranteed by Rust ownership model
- **Constant Time**: Cryptographic operations should be constant time where possible
- **Side-channel Resistance**: Implementation should consider side-channel attack mitigations
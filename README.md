# Talos Core (Rust)

**Repo Role**: High-performance cryptographic kernel and shared logic for the Talos ecosystem.

## Abstract

`talos-core-rs` provides the foundational cryptographic primitives and state machine logic for the Talos Protocol. Written in Rust for safety and performance, it serves as the reference implementation for core algorithms and exposes a foreign function interface (FFI) for other languages.

## Introduction

The security of the Talos Protocol relies on the correct implementation of the Double Ratchet Algorithm and X3DH key exchange. `talos-core-rs` isolates this complex logic into a single, audit-ready codebase, preventing implementation divergence across the ecosystem.

## System Architecture

```mermaid
graph TD
    Kernel[Talos Core (Rust)]

    subgraph Bindings_Layer[Bindings]
        Py[Python Bindings]
        Node[Node.js Bindings]
    end

    Kernel --> Py
    Kernel --> Node
```

This repository is the verified kernel that powers high-performance SDKs.

## Technical Design

### Modules

- **ratchet**: Double Ratchet state machine.
- **x3dh**: Extended Triple Diffie-Hellman key agreement.
- **crypto**: Wrappers for X25519, Ed25519, ChaCha20-Poly1305.

### Data Formats

- **Serialization**: Serde-compatible binary formats.

## Evaluation

**Status**: Core Component.

- **Coverage**: 100% unit test coverage for cryptographic primitives.
- **Safety**: No `unsafe` blocks (except FFI/PyO3 boundaries).

## Usage

### Quickstart

```bash
cargo build --release
```

### Common Workflows

1.  **Build FFI**: `maturin develop`
2.  **Run Benchmarks**: `cargo bench`

## Operational Interface

- `make test`: Run cargo tests.
- `scripts/test.sh`: CI entrypoint.

## Security Considerations

- **Threat Model**: Side-channel attacks, memory safety exploits.
- **Guarantees**:
  - **Memory Safety**: Guaranteed by Rust ownership model.
  - **Constant Time**: Cryptographic operations are constant time where possible.

## References

1.  [Mathematical Security Proof](https://github.com/talosprotocol/talos/wiki/Mathematical-Security-Proof)
2.  [Talos Contracts](https://github.com/talosprotocol/talos-contracts)
3.  [Cryptography Guide](https://github.com/talosprotocol/talos/wiki/Cryptography)

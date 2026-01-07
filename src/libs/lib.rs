//! Talos Protocol Core Rust Kernel
//!
//! This crate provides the core cryptographic primitives and encoding
//! functions for the Talos Protocol SDK.

#![allow(clippy::useless_conversion)]

#[path = "../adapters/mod.rs"]
pub mod adapters;

#[path = "../domain/mod.rs"]
pub mod domain;

#[path = "../errors/mod.rs"]
pub mod errors;

#[path = "../ports/mod.rs"]
pub mod ports;

// Local modules (in src/libs/)
pub mod canonical;
pub mod encoding;

// Re-export for convenience
pub use adapters::*;
pub use errors::*;
// Exporting contents of local modules if desired, or just the modules themselves.
// The previous lib.rs exported `libs::*`.
// Now `libs` doesn't exist as a module suffix.
// We can re-export canonical/encoding content if we want top-level access,
// or just keep them as modules.
// Standard rust lib usually keeps them in modules.
// But let's check what `wrap_pyfunction!` expects.

use pyo3::prelude::*;

/// A Python module implemented in Rust.
#[pymodule]
fn talos_core_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Path string "encoding::derive_cursor" usually implied from rust path?
    // wrap_pyfunction takes the function item.
    m.add_function(wrap_pyfunction!(encoding::derive_cursor, m)?)?;
    m.add_class::<adapters::python::PyWallet>()?;
    Ok(())
}

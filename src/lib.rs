//! Talos Protocol Core Rust Kernel
//!
//! This crate provides the core cryptographic primitives and encoding
//! functions for the Talos Protocol SDK.

#![allow(clippy::useless_conversion)]

mod canonical;
mod crypto;
mod encoding;
mod errors;
mod wallet;

pub use canonical::*;
pub use crypto::*;
pub use encoding::*;
pub use errors::*;
pub use wallet::*;

use pyo3::prelude::*;

/// A Python module implemented in Rust.
#[pymodule]
fn talos_core_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encoding::derive_cursor, m)?)?;
    m.add_class::<wallet::PyWallet>()?;
    Ok(())
}

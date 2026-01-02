use pyo3::prelude::*;
use base64::{Engine as _, engine::general_purpose};

/// Derive a cursor from timestamp and event ID.
/// Format: base64url(timestamp:event_id)
#[pyfunction]
fn derive_cursor(timestamp: u64, event_id: &str) -> PyResult<String> {
    let payload = format!("{}:{}", timestamp, event_id);
    // Use URL_SAFE_NO_PAD for standard "base64url"
    let output = general_purpose::URL_SAFE_NO_PAD.encode(payload);
    Ok(output)
}

/// A Python module implemented in Rust.
#[pymodule]
fn talos_core_rs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(derive_cursor, m)?)?;
    Ok(())
}

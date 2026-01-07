//! Encoding utilities for Talos Protocol.

use base64::{engine::general_purpose, Engine as _};
use pyo3::prelude::*;

/// Base64url encode without padding.
pub fn base64url_encode(data: &[u8]) -> String {
    general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Base64url decode.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    general_purpose::URL_SAFE_NO_PAD.decode(s)
}

/// Derive a cursor from timestamp and event ID.
/// Format: base64url(timestamp:event_id)
#[pyfunction]
#[allow(clippy::useless_conversion)]
pub fn derive_cursor(timestamp: u64, event_id: &str) -> PyResult<String> {
    let payload = format!("{}:{}", timestamp, event_id);
    let output = base64url_encode(payload.as_bytes());
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"hello world";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }
}

//! Canonical JSON encoding for Talos Protocol.

use serde::ser::Error;
use serde::Serialize;

/// Serialize a value to canonical JSON (RFC 8785).
pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    serde_jcs::to_string(value).map_err(serde_json::Error::custom)
}

/// Serialize to canonical JSON bytes.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    serde_jcs::to_vec(value).map_err(serde_json::Error::custom)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_key_ordering() {
        let mut map = HashMap::new();
        map.insert("z", 1);
        map.insert("a", 2);
        map.insert("m", 3);
        let result = canonical_json(&map).unwrap();
        assert_eq!(result, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_no_whitespace() {
        let map: HashMap<&str, i32> = [("key", 1)].into_iter().collect();
        let result = canonical_json(&map).unwrap();
        assert!(!result.contains(' '));
        assert!(!result.contains('\n'));
    }
}

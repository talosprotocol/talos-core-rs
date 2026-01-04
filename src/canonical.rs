//! Canonical JSON encoding for Talos Protocol.

use serde::Serialize;

/// Serialize a value to canonical JSON.
/// Rules:
/// - Keys sorted lexicographically
/// - No whitespace outside strings
/// - UTF-8 encoding
pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, serde_json::Error> {
    // serde_json with default settings already does:
    // - No whitespace
    // - UTF-8
    // We need to sort keys which requires a custom approach
    let json_value = serde_json::to_value(value)?;
    let sorted = sort_json_keys(&json_value);
    serde_json::to_string(&sorted)
}

/// Serialize to canonical JSON bytes.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    canonical_json(value).map(|s| s.into_bytes())
}

fn sort_json_keys(value: &serde_json::Value) -> serde_json::Value {
    use serde_json::Value;

    match value {
        Value::Object(map) => {
            let mut sorted: Vec<_> = map.iter().collect();
            sorted.sort_by(|a, b| a.0.cmp(b.0));
            let sorted_map: serde_json::Map<String, Value> = sorted
                .into_iter()
                .map(|(k, v)| (k.clone(), sort_json_keys(v)))
                .collect();
            Value::Object(sorted_map)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(sort_json_keys).collect()),
        _ => value.clone(),
    }
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

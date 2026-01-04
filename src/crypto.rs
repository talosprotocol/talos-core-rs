//! Cryptographic primitives for Talos Protocol.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

/// Sign a message with Ed25519.
/// Returns a 64-byte signature.
pub fn ed25519_sign(message: &[u8], secret_key: &[u8; 32]) -> [u8; 64] {
    let signing_key = SigningKey::from_bytes(secret_key);
    let signature = signing_key.sign(message);
    signature.to_bytes()
}

/// Verify an Ed25519 signature.
pub fn ed25519_verify(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
    let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let sig = Signature::from_bytes(signature);
    verifying_key.verify(message, &sig).is_ok()
}

/// Get the public key from a secret key.
pub fn ed25519_public_key(secret_key: &[u8; 32]) -> [u8; 32] {
    let signing_key = SigningKey::from_bytes(secret_key);
    signing_key.verifying_key().to_bytes()
}

/// SHA256 hash.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let secret = [0u8; 32];
        let public = ed25519_public_key(&secret);
        let message = b"hello";
        let signature = ed25519_sign(message, &secret);
        assert!(ed25519_verify(message, &signature, &public));
    }

    #[test]
    fn test_verify_wrong_message() {
        let secret = [0u8; 32];
        let public = ed25519_public_key(&secret);
        let signature = ed25519_sign(b"hello", &secret);
        assert!(!ed25519_verify(b"world", &signature, &public));
    }
}

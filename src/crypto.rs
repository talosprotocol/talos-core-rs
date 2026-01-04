//! Cryptographic primitives for Talos Protocol.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

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

// ... existing ed25519 ...

/// Setup for X25519 Keypair
#[derive(Debug)]
pub struct KeyPairX25519 {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

/// Generate new X25519 keypair.
pub fn x25519_generate() -> KeyPairX25519 {
    let secret = StaticSecret::random_from_rng(rand::thread_rng());
    let public = PublicKey::from(&secret);
    KeyPairX25519 {
        public: *public.as_bytes(),
        private: secret.to_bytes(),
    }
}

/// Perform X25519 DH.
pub fn x25519_dh(private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private);
    let public_key = PublicKey::from(*public);
    *secret.diffie_hellman(&public_key).as_bytes()
}

/// HKDF-SHA256 Derive.
pub fn hkdf_derive(ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm).expect("HKDF expand failed");
    okm
}

/// ChaCha20Poly1305 Encrypt.
/// Returns Nonce + Ciphertext
pub fn aead_encrypt(key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = Nonce::from_slice(&nonce_bytes);

    let payload = Payload {
        msg: plaintext,
        aad: ad,
    };

    let ciphertext = cipher.encrypt(nonce, payload).expect("encryption failed");

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    output
}

/// ChaCha20Poly1305 Decrypt.
/// Expects Nonce (12) + Ciphertext
pub fn aead_decrypt(key: &[u8; 32], data: &[u8], ad: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < 12 {
        return Err("Data too short".to_string());
    }

    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(&data[..12]);
    let ciphertext = &data[12..];

    let payload = Payload {
        msg: ciphertext,
        aad: ad,
    };

    cipher.decrypt(nonce, payload).map_err(|e| e.to_string())
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

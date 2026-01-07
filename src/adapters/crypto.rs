use crate::errors::{TalosError, TalosResult};
use crate::ports::crypto::CryptoProvider;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct RealCryptoProvider;

impl CryptoProvider for RealCryptoProvider {
    fn ed25519_sign(&self, message: &[u8], secret_key: &[u8; 32]) -> [u8; 64] {
        let signing_key = SigningKey::from_bytes(secret_key);
        let signature = signing_key.sign(message);
        signature.to_bytes()
    }

    fn ed25519_verify(&self, message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
        let Ok(verifying_key) = VerifyingKey::from_bytes(public_key) else {
            return false;
        };
        let sig = Signature::from_bytes(signature);
        verifying_key.verify(message, &sig).is_ok()
    }

    fn ed25519_public_key(&self, secret_key: &[u8; 32]) -> [u8; 32] {
        let signing_key = SigningKey::from_bytes(secret_key);
        signing_key.verifying_key().to_bytes()
    }

    fn x25519_generate(&self) -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let public = PublicKey::from(&secret);
        (*public.as_bytes(), secret.to_bytes())
    }

    fn x25519_dh(&self, private: &[u8; 32], public: &[u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(*private);
        let public_key = PublicKey::from(*public);
        *secret.diffie_hellman(&public_key).as_bytes()
    }

    fn hkdf_derive(&self, ikm: &[u8], info: &[u8], length: usize) -> Vec<u8> {
        let hk = Hkdf::<Sha256>::new(None, ikm);
        let mut okm = vec![0u8; length];
        hk.expand(info, &mut okm).expect("HKDF expand failed");
        okm
    }

    fn aead_encrypt(&self, key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Vec<u8> {
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

    fn aead_decrypt(&self, key: &[u8; 32], data: &[u8], ad: &[u8]) -> TalosResult<Vec<u8>> {
        if data.len() < 12 {
            return Err(TalosError::CryptoError("Data too short".to_string()));
        }

        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];

        let payload = Payload {
            msg: ciphertext,
            aad: ad,
        };

        cipher
            .decrypt(nonce, payload)
            .map_err(|e| TalosError::CryptoError(e.to_string()))
    }

    fn sha256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn random_bytes(&self, dest: &mut [u8]) {
        rand::thread_rng().fill_bytes(dest);
    }
}

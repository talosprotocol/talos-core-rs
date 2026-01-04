//! Wallet implementation for Talos Protocol.

use crate::crypto::{ed25519_public_key, ed25519_sign, ed25519_verify, sha256};
use pyo3::prelude::*;
use rand::RngCore;

/// Multicodec prefix for Ed25519 public key (0xed01)
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Wallet for identity and signing.
pub struct Wallet {
    secret_key: [u8; 32],
    public_key: [u8; 32],
    name: Option<String>,
}

impl Wallet {
    /// Generate a new wallet with random keypair.
    pub fn generate(name: Option<String>) -> Self {
        let mut secret_key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_key);
        let public_key = ed25519_public_key(&secret_key);
        Self {
            secret_key,
            public_key,
            name,
        }
    }

    /// Create a wallet from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32], name: Option<String>) -> Self {
        let public_key = ed25519_public_key(&seed);
        Self {
            secret_key: seed,
            public_key,
            name,
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Get the wallet name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Convert to DID string.
    pub fn to_did(&self) -> String {
        let mut multicodec_key = Vec::with_capacity(34);
        multicodec_key.extend_from_slice(&ED25519_MULTICODEC);
        multicodec_key.extend_from_slice(&self.public_key);
        format!("did:key:z{}", bs58::encode(&multicodec_key).into_string())
    }

    /// Get hex-encoded address (SHA256 of public key).
    pub fn address(&self) -> String {
        let hash = sha256(&self.public_key);
        hash.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        ed25519_sign(message, &self.secret_key)
    }

    /// Verify a signature.
    pub fn verify(message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool {
        ed25519_verify(message, signature, public_key)
    }
}

/// Python wrapper for Wallet.
#[pyclass(name = "Wallet")]
pub struct PyWallet {
    inner: Wallet,
}

#[pymethods]
impl PyWallet {
    #[staticmethod]
    #[pyo3(signature = (name=None))]
    fn generate(name: Option<String>) -> Self {
        Self {
            inner: Wallet::generate(name),
        }
    }

    #[staticmethod]
    #[pyo3(signature = (seed, name=None))]
    fn from_seed(seed: Vec<u8>, name: Option<String>) -> PyResult<Self> {
        if seed.len() != 32 {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Seed must be 32 bytes, got {}",
                seed.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&seed);
        Ok(Self {
            inner: Wallet::from_seed(arr, name),
        })
    }

    fn to_did(&self) -> String {
        self.inner.to_did()
    }

    fn address(&self) -> String {
        self.inner.address()
    }

    fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        self.inner.sign(&message).to_vec()
    }

    #[staticmethod]
    fn verify(message: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
        if signature.len() != 64 || public_key.len() != 32 {
            return false;
        }
        let mut sig = [0u8; 64];
        let mut pk = [0u8; 32];
        sig.copy_from_slice(&signature);
        pk.copy_from_slice(&public_key);
        Wallet::verify(&message, &sig, &pk)
    }

    #[getter]
    fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    #[getter]
    fn name(&self) -> Option<String> {
        self.inner.name().map(|s| s.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_wallet() {
        let wallet = Wallet::generate(Some("test".to_string()));
        assert_eq!(wallet.name(), Some("test"));
        assert!(wallet.to_did().starts_with("did:key:z"));
    }

    #[test]
    fn test_from_seed_deterministic() {
        let seed = [0u8; 32];
        let w1 = Wallet::from_seed(seed, None);
        let w2 = Wallet::from_seed(seed, None);
        assert_eq!(w1.public_key(), w2.public_key());
        assert_eq!(w1.to_did(), w2.to_did());
    }

    #[test]
    fn test_sign_verify() {
        let wallet = Wallet::generate(None);
        let message = b"hello";
        let signature = wallet.sign(message);
        assert!(Wallet::verify(message, &signature, &wallet.public_key()));
    }
}

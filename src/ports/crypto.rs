use crate::errors::TalosResult;

pub trait CryptoProvider: Send + Sync {
    fn ed25519_sign(&self, message: &[u8], secret_key: &[u8; 32]) -> [u8; 64];
    fn ed25519_verify(&self, message: &[u8], signature: &[u8; 64], public_key: &[u8; 32]) -> bool;
    fn ed25519_public_key(&self, secret_key: &[u8; 32]) -> [u8; 32];

    fn x25519_generate(&self) -> ([u8; 32], [u8; 32]); // Returns (public, private)
    fn x25519_dh(&self, private: &[u8; 32], public: &[u8; 32]) -> [u8; 32];

    fn hkdf_derive(&self, ikm: &[u8], info: &[u8], length: usize) -> Vec<u8>;

    fn aead_encrypt(&self, key: &[u8; 32], plaintext: &[u8], ad: &[u8]) -> Vec<u8>;
    fn aead_decrypt(&self, key: &[u8; 32], data: &[u8], ad: &[u8]) -> TalosResult<Vec<u8>>;

    fn sha256(&self, data: &[u8]) -> [u8; 32];
    fn hmac_sha256(&self, key: &[u8], data: &[u8]) -> [u8; 32];
    fn random_bytes(&self, dest: &mut [u8]);
}

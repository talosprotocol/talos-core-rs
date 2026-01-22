use crate::ports::crypto::CryptoProvider;

/// Multicodec prefix for Ed25519 public key (0xed01)
const ED25519_MULTICODEC: [u8; 2] = [0xed, 0x01];

/// Wallet for identity and signing.
use std::fmt;

/// Wallet for identity and signing.
#[derive(Clone)]
pub struct Wallet {
    pub secret_key: [u8; 32],
    pub public_key: [u8; 32],
    pub name: Option<String>,
}

impl fmt::Debug for Wallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Wallet")
            .field("secret_key", &"<REDACTED>")
            .field("public_key", &hex::encode(self.public_key))
            .field("name", &self.name)
            .finish()
    }
}

impl Wallet {
    /// Generate a new wallet with random keypair.
    pub fn generate(name: Option<String>, provider: &impl CryptoProvider) -> Self {
        let mut secret_key = [0u8; 32];
        provider.random_bytes(&mut secret_key);
        let public_key = provider.ed25519_public_key(&secret_key);
        Self {
            secret_key,
            public_key,
            name,
        }
    }

    /// Create a wallet from a 32-byte seed.
    pub fn from_seed(seed: [u8; 32], name: Option<String>, provider: &impl CryptoProvider) -> Self {
        let public_key = provider.ed25519_public_key(&seed);
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
    pub fn address(&self, provider: &impl CryptoProvider) -> String {
        let hash = provider.sha256(&self.public_key);
        hash.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8], provider: &impl CryptoProvider) -> [u8; 64] {
        provider.ed25519_sign(message, &self.secret_key)
    }

    /// Verify a signature.
    pub fn verify(
        message: &[u8],
        signature: &[u8; 64],
        public_key: &[u8; 32],
        provider: &impl CryptoProvider,
    ) -> bool {
        provider.ed25519_verify(message, signature, public_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::crypto::RealCryptoProvider;

    #[test]
    fn test_generate_wallet() {
        let provider = RealCryptoProvider;
        let wallet = Wallet::generate(Some("test".to_string()), &provider);
        assert_eq!(wallet.name(), Some("test"));
        assert!(wallet.to_did().starts_with("did:key:z"));
    }

    #[test]
    fn test_from_seed_deterministic() {
        let provider = RealCryptoProvider;
        let seed = [0u8; 32];
        let w1 = Wallet::from_seed(seed, None, &provider);
        let w2 = Wallet::from_seed(seed, None, &provider);
        assert_eq!(w1.public_key(), w2.public_key());
        assert_eq!(w1.to_did(), w2.to_did());
    }

    #[test]
    fn test_sign_verify() {
        let provider = RealCryptoProvider;
        let wallet = Wallet::generate(None, &provider);
        let message = b"hello";
        let signature = wallet.sign(message, &provider);
        assert!(Wallet::verify(
            message,
            &signature,
            &wallet.public_key(),
            &provider
        ));
    }
}

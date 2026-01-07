use crate::errors::{TalosError, TalosResult};
use crate::ports::crypto::CryptoProvider;
use serde::{Deserialize, Serialize};

// Constants
const MAX_SKIP: usize = 1000;
pub const INFO_ROOT: &[u8] = b"talos-double-ratchet-root";
pub const INFO_CHAIN: &[u8] = b"talos-double-ratchet-chain";
pub const INFO_MESSAGE: &[u8] = b"talos-double-ratchet-message";

// Key Derivation Helpers
fn kdf_rk(rk: &[u8], dh_out: &[u8], provider: &impl CryptoProvider) -> (Vec<u8>, Vec<u8>) {
    let mut input = Vec::with_capacity(dh_out.len() + rk.len());
    input.extend_from_slice(dh_out);
    input.extend_from_slice(rk);
    let output = provider.hkdf_derive(&input, INFO_ROOT, 64);
    (output[..32].to_vec(), output[32..].to_vec())
}

fn kdf_ck(ck: &[u8], provider: &impl CryptoProvider) -> (Vec<u8>, Vec<u8>) {
    let output = provider.hkdf_derive(ck, INFO_CHAIN, 64);
    (output[..32].to_vec(), output[32..].to_vec())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrekeyBundle {
    pub identity_key: [u8; 32],
    pub signed_prekey: [u8; 32],
    pub prekey_signature: Vec<u8>,
    pub one_time_prekey: Option<[u8; 32]>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    #[serde(rename = "dh")]
    pub public_key: [u8; 32],
    pub pn: u32,
    pub n: u32,
}

impl MessageHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.public_key);
        bytes.extend_from_slice(&self.pn.to_be_bytes());
        bytes.extend_from_slice(&self.n.to_be_bytes());
        bytes
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyPair {
    pub public: [u8; 32],
    pub private: [u8; 32],
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SkippedKey {
    pub public_key: [u8; 32],
    pub n: u32,
    pub message_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RatchetState {
    pub dh_pair: KeyPair,
    pub dh_remote: [u8; 32],
    pub root_key: Vec<u8>,
    pub chain_key_s: Vec<u8>,
    pub chain_key_r: Vec<u8>,
    pub n_s: u32,
    pub n_r: u32,
    pub pn: u32,
    pub skipped_keys: Vec<SkippedKey>,
}

pub struct Session {
    pub state: RatchetState,
}

impl Session {
    pub fn new(state: RatchetState) -> Self {
        Self { state }
    }

    pub fn encrypt(
        &mut self,
        plaintext: &[u8],
        provider: &impl CryptoProvider,
    ) -> TalosResult<Vec<u8>> {
        let (next_ck, mk) = kdf_ck(&self.state.chain_key_s, provider);
        self.state.chain_key_s = next_ck;

        let header = MessageHeader {
            public_key: self.state.dh_pair.public,
            pn: self.state.pn,
            n: self.state.n_s,
        };

        self.state.n_s += 1;

        let header_bytes = header.to_bytes();
        let ciphertext =
            provider.aead_encrypt(mk.as_slice().try_into().unwrap(), plaintext, &header_bytes);

        // Serialize header + ciphertext
        let mut output = Vec::new();
        let header_json =
            serde_json::to_string(&header).map_err(|e| TalosError::Serialization(e.to_string()))?;
        let header_len = (header_json.len() as u32).to_be_bytes();

        output.extend_from_slice(&header_len);
        output.extend_from_slice(header_json.as_bytes());
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    pub fn decrypt(
        &mut self,
        message: &[u8],
        provider: &impl CryptoProvider,
    ) -> TalosResult<Vec<u8>> {
        if message.len() < 4 {
            return Err(TalosError::Protocol("Message too short".to_string()));
        }

        let header_len = u32::from_be_bytes(message[..4].try_into().unwrap()) as usize;
        if message.len() < 4 + header_len {
            return Err(TalosError::Protocol(
                "Message content too short for header".to_string(),
            ));
        }

        let header_json = &message[4..4 + header_len];
        let header: MessageHeader = serde_json::from_slice(header_json)
            .map_err(|e| TalosError::Serialization(e.to_string()))?;

        let ciphertext = &message[4 + header_len..];

        // 1. Try skipped keys
        let header_bytes = header.to_bytes();
        if let Some(plaintext) = self.try_skipped_keys(&header, ciphertext, &header_bytes, provider)
        {
            return Ok(plaintext);
        }

        // 2. Ratchet if new public key
        if header.public_key != self.state.dh_remote {
            self.skip_message_keys(header.pn, provider)?;
            self.dh_ratchet(&header, provider);
        }

        // 3. Skip message keys in current chain
        self.skip_message_keys(header.n, provider)?;

        // 4. Decrypt
        let (next_ck, mk) = kdf_ck(&self.state.chain_key_r, provider);
        self.state.chain_key_r = next_ck;
        self.state.n_r += 1;

        let plaintext =
            provider.aead_decrypt(mk.as_slice().try_into().unwrap(), ciphertext, &header_bytes)?;

        Ok(plaintext)
    }

    pub fn try_skipped_keys(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        ad: &[u8],
        provider: &impl CryptoProvider,
    ) -> Option<Vec<u8>> {
        if let Some(index) = self
            .state
            .skipped_keys
            .iter()
            .position(|k| k.public_key == header.public_key && k.n == header.n)
        {
            let key = self.state.skipped_keys.remove(index);

            if let Ok(plaintext) = provider.aead_decrypt(
                key.message_key.as_slice().try_into().unwrap(),
                ciphertext,
                ad,
            ) {
                return Some(plaintext);
            }
        }
        None
    }

    pub fn skip_message_keys(
        &mut self,
        until: u32,
        provider: &impl CryptoProvider,
    ) -> TalosResult<()> {
        if self.state.n_r + (MAX_SKIP as u32) < until {
            return Err(TalosError::Protocol("Too many skipped keys".to_string()));
        }

        while self.state.n_r < until {
            let (next_ck, mk) = kdf_ck(&self.state.chain_key_r, provider);
            self.state.chain_key_r = next_ck;

            self.state.skipped_keys.push(SkippedKey {
                public_key: self.state.dh_remote,
                n: self.state.n_r,
                message_key: mk,
            });

            self.state.n_r += 1;
        }
        Ok(())
    }

    pub fn dh_ratchet(&mut self, header: &MessageHeader, provider: &impl CryptoProvider) {
        self.state.pn = self.state.n_s;
        self.state.n_s = 0;
        self.state.n_r = 0;
        self.state.dh_remote = header.public_key;

        let dh_out = provider.x25519_dh(&self.state.dh_pair.private, &self.state.dh_remote);
        let (next_rk, next_ck) = kdf_rk(&self.state.root_key, &dh_out, provider);
        self.state.root_key = next_rk;
        self.state.chain_key_r = next_ck;

        let (new_public, new_private) = provider.x25519_generate();
        self.state.dh_pair = KeyPair {
            public: new_public,
            private: new_private,
        };

        let dh_out = provider.x25519_dh(&self.state.dh_pair.private, &self.state.dh_remote);
        let (next_rk, next_ck) = kdf_rk(&self.state.root_key, &dh_out, provider);
        self.state.root_key = next_rk;
        self.state.chain_key_s = next_ck;
    }

    pub fn initialize_sending_chain(&mut self, provider: &impl CryptoProvider) -> TalosResult<()> {
        let dh_out = provider.x25519_dh(&self.state.dh_pair.private, &self.state.dh_remote);
        let (next_rk, next_ck) = kdf_rk(&self.state.root_key, &dh_out, provider);
        self.state.root_key = next_rk;
        self.state.chain_key_s = next_ck;
        Ok(())
    }
}

pub struct SessionManager {
    identity: KeyPair,
    _prekey_bundle: Option<PrekeyBundle>,
    signed_prekey_pair: Option<KeyPair>,
}

impl SessionManager {
    pub fn new(identity_public: [u8; 32], identity_private: [u8; 32]) -> Self {
        Self {
            identity: KeyPair {
                public: identity_public,
                private: identity_private,
            },
            _prekey_bundle: None,
            signed_prekey_pair: None,
        }
    }

    // Conformance helper to inject SPK
    pub fn set_signed_prekey(
        &mut self,
        spk_public: [u8; 32],
        spk_private: [u8; 32],
        _sig: Vec<u8>,
    ) {
        self.signed_prekey_pair = Some(KeyPair {
            public: spk_public,
            private: spk_private,
        });
        // We could also update prekey_bundle if needed, but not strictly required for conformance test usage
    }

    pub fn get_prekey_bundle(&mut self, provider: &impl CryptoProvider) -> PrekeyBundle {
        if let Some(pair) = &self.signed_prekey_pair {
            // Return existing if already set (simplification)
            return PrekeyBundle {
                identity_key: self.identity.public,
                signed_prekey: pair.public,
                prekey_signature: vec![0u8; 64], // TODO: real signature
                one_time_prekey: None,
            };
        }

        let (spk_pub, spk_priv) = provider.x25519_generate();
        let pair = KeyPair {
            public: spk_pub,
            private: spk_priv,
        };
        self.signed_prekey_pair = Some(pair);

        PrekeyBundle {
            identity_key: self.identity.public,
            signed_prekey: spk_pub,
            prekey_signature: vec![0u8; 64],
            one_time_prekey: None,
        }
    }

    pub fn create_initiator(
        &self,
        remote_bundle: &PrekeyBundle,
        provider: &impl CryptoProvider,
    ) -> TalosResult<Session> {
        let (ephemeral_pub, ephemeral_priv) = provider.x25519_generate();

        // DH between our ephemeral and their signed prekey
        // This calculates the initial entropy, which for this simplified implementation drives
        // the initial Root Key / Chain Key derivation.
        // Note: Full X3DH would involve Identity keys too. This is simplified.

        let state = RatchetState {
            dh_pair: KeyPair {
                public: ephemeral_pub,
                private: ephemeral_priv,
            },
            dh_remote: remote_bundle.signed_prekey,
            root_key: vec![0u8; 32], // Starting with zero RK
            chain_key_s: vec![0u8; 32],
            chain_key_r: vec![0u8; 32],
            n_s: 0,
            n_r: 0,
            pn: 0,
            skipped_keys: Vec::new(),
        };

        let mut session = Session::new(state);
        session.initialize_sending_chain(provider)?;
        Ok(session)
    }

    pub fn create_responder(
        &self,
        remote_dh_public: &[u8],
        _remote_identity: &[u8],
        provider: &impl CryptoProvider,
    ) -> TalosResult<Session> {
        let signed_prekey = self.signed_prekey_pair.as_ref().ok_or_else(|| {
            TalosError::Protocol("No signed prekey available for responder".into())
        })?;

        let mut remote_pk = [0u8; 32];
        if remote_dh_public.len() != 32 {
            return Err(TalosError::Protocol("Invalid remote key length".into()));
        }
        remote_pk.copy_from_slice(remote_dh_public);

        // Bob's initial state matches Alice's view:
        // Bob's 'dh_pair' is his Signed Prekey (because that's what Alice used).
        // Bob's 'dh_remote' is Alice's Ephemeral (passed in).

        let mut state = RatchetState {
            dh_pair: KeyPair {
                public: signed_prekey.public,
                private: signed_prekey.private,
            },
            dh_remote: remote_pk,
            root_key: vec![0u8; 32], // Starting with zero RK
            chain_key_s: vec![0u8; 32],
            chain_key_r: vec![0u8; 32],
            n_s: 0,
            n_r: 0,
            pn: 0,
            skipped_keys: Vec::new(),
        };

        // Alice did `initialize_sending_chain`:
        // DH(AliceEph_priv, BobSPK_pub) -> KDF -> (next_rk, next_ck_s)

        // Bob must do receive equivalent:
        // DH(BobSPK_priv, AliceEph_pub) -> KDF -> (next_rk, next_ck_r)

        let dh_out = provider.x25519_dh(&state.dh_pair.private, &state.dh_remote);
        let (next_rk, next_ck) = kdf_rk(&state.root_key, &dh_out, provider);
        state.root_key = next_rk;
        state.chain_key_r = next_ck;

        Ok(Session::new(state))
    }
}

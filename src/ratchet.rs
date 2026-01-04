//! Double Ratchet Protocol Implementation.

use crate::crypto::{self, KeyPairX25519};
use crate::errors::{TalosError, TalosResult};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

// Constants
const MAX_SKIP: usize = 1000;
const INFO_ROOT: &[u8] = b"talos-double-ratchet-root";
const INFO_CHAIN: &[u8] = b"talos-double-ratchet-chain";
const INFO_MESSAGE: &[u8] = b"talos-double-ratchet-message";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PrekeyBundle {
    #[serde(with = "base64_serde")]
    pub identity_key: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub signed_prekey: Vec<u8>,
    #[serde(with = "base64_serde")]
    pub prekey_signature: Vec<u8>,
    #[serde(with = "base64_serde_opt")]
    pub one_time_prekey: Option<Vec<u8>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MessageHeader {
    #[serde(with = "base64_serde", rename = "dh")]
    pub dh_public: Vec<u8>,
    #[serde(rename = "pn")]
    pub previous_chain_length: u32,
    #[serde(rename = "n")]
    pub message_number: u32,
}

impl MessageHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct KeyPair {
    #[serde(with = "base64_serde", rename = "public")]
    pub public_key: Vec<u8>,
    #[serde(with = "base64_serde", rename = "private")]
    pub private_key: Vec<u8>,
    #[serde(rename = "type")]
    pub key_type: String,
}

impl From<KeyPairX25519> for KeyPair {
    fn from(kp: KeyPairX25519) -> Self {
        KeyPair {
            public_key: kp.public.to_vec(),
            private_key: kp.private.to_vec(),
            key_type: "x25519".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SkippedKey {
    #[serde(with = "base64_serde")]
    pub dh: Vec<u8>,
    pub n: u32,
    #[serde(with = "base64_serde")]
    pub key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RatchetState {
    pub dh_keypair: KeyPair,
    #[serde(with = "base64_serde_opt")]
    pub dh_remote: Option<Vec<u8>>,
    #[serde(with = "base64_serde")]
    pub root_key: Vec<u8>,
    #[serde(with = "base64_serde_opt")]
    pub chain_key_send: Option<Vec<u8>>,
    #[serde(with = "base64_serde_opt")]
    pub chain_key_recv: Option<Vec<u8>>,

    pub send_count: u32,
    pub recv_count: u32,
    pub prev_send_count: u32,

    // We store skipped keys as a list for serialization, but map in memory would be better?
    // For now mirroring the python structure which might use list of dicts for skipped in JSON
    // The spec says: skipped_keys: dict[tuple[bytes, int], bytes]
    // Python Pydantic serializer converts this to list of objects.
    // We will use Vec<SkippedKey> and manual lookup.
    #[serde(default)]
    pub skipped_keys: Vec<SkippedKey>,
}

pub struct Session {
    pub state: RatchetState,
}

impl Session {
    pub fn new(state: RatchetState) -> Self {
        Self { state }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> TalosResult<Vec<u8>> {
        if self.state.chain_key_send.is_none() {
            self.initialize_sending_chain()?;
        }

        let ck_send = self.state.chain_key_send.as_ref().unwrap();
        let (mk, next_ck) = kdf_ck(ck_send);
        self.state.chain_key_send = Some(next_ck);

        let header = MessageHeader {
            dh_public: self.state.dh_keypair.public_key.clone(),
            previous_chain_length: self.state.prev_send_count,
            message_number: self.state.send_count,
        };

        let header_bytes = header.to_bytes();
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&mk);

        let ciphertext = crypto::aead_encrypt(&key_arr, plaintext, &header_bytes);

        self.state.send_count += 1;

        let header_len = (header_bytes.len() as u16).to_be_bytes();
        let mut output = Vec::new();
        output.extend_from_slice(&header_len);
        output.extend_from_slice(&header_bytes);
        output.extend_from_slice(&ciphertext);

        Ok(output)
    }

    pub fn decrypt(&mut self, message: &[u8]) -> TalosResult<Vec<u8>> {
        if message.len() < 2 {
            return Err(TalosError::InvalidInput("Message too short".into()));
        }
        let header_len = u16::from_be_bytes([message[0], message[1]]) as usize;
        if message.len() < 2 + header_len {
            return Err(TalosError::InvalidInput("Message incomplete".into()));
        }

        let header_bytes = &message[2..2 + header_len];
        let ciphertext = &message[2 + header_len..];

        let header: MessageHeader = serde_json::from_slice(header_bytes)
            .map_err(|e| TalosError::FrameInvalid(e.to_string()))?;

        // Try skipped keys
        if let Some(pt) = self.try_skipped_keys(&header, ciphertext, header_bytes) {
            return Ok(pt);
        }

        // Ratchet if new DH
        if Some(&header.dh_public) != self.state.dh_remote.as_ref() {
            self.skip_message_keys(header.previous_chain_length)?;
            self.dh_ratchet(&header);
        }

        self.skip_message_keys(header.message_number)?;

        if self.state.chain_key_recv.is_none() {
            return Err(TalosError::RatchetError("No receiving chain key".into()));
        }

        let ck_recv = self.state.chain_key_recv.as_ref().unwrap();
        let (mk, next_ck) = kdf_ck(ck_recv);
        self.state.chain_key_recv = Some(next_ck);
        self.state.recv_count += 1;

        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&mk);

        crypto::aead_decrypt(&key_arr, ciphertext, header_bytes).map_err(TalosError::CryptoError)
    }

    fn try_skipped_keys(
        &mut self,
        header: &MessageHeader,
        ciphertext: &[u8],
        ad: &[u8],
    ) -> Option<Vec<u8>> {
        if let Some(idx) = self
            .state
            .skipped_keys
            .iter()
            .position(|k| k.dh == header.dh_public && k.n == header.message_number)
        {
            let sk = self.state.skipped_keys.remove(idx);
            let mut key_arr = [0u8; 32];
            key_arr.copy_from_slice(&sk.key);
            return crypto::aead_decrypt(&key_arr, ciphertext, ad).ok();
        }
        None
    }

    fn skip_message_keys(&mut self, until: u32) -> TalosResult<()> {
        if self.state.chain_key_recv.is_none() {
            return Ok(());
        }

        if self.state.recv_count + (MAX_SKIP as u32) < until {
            return Err(TalosError::RatchetError("Too many skipped messages".into()));
        }

        while self.state.recv_count < until {
            let ck = self.state.chain_key_recv.as_ref().unwrap();
            let (mk, next_ck) = kdf_ck(ck);
            self.state.chain_key_recv = Some(next_ck);

            self.state.skipped_keys.push(SkippedKey {
                dh: self.state.dh_remote.clone().unwrap(),
                n: self.state.recv_count,
                key: mk,
            });
            self.state.recv_count += 1;
        }
        Ok(())
    }

    fn dh_ratchet(&mut self, header: &MessageHeader) {
        self.state.prev_send_count = self.state.send_count;
        self.state.send_count = 0;
        self.state.recv_count = 0;
        self.state.dh_remote = Some(header.dh_public.clone());

        let rk = &self.state.root_key;
        let dh_recv = crypto::x25519_dh(
            array_ref(&self.state.dh_keypair.private_key),
            array_ref(self.state.dh_remote.as_ref().unwrap()),
        );
        let (new_rk, ck_recv) = kdf_rk(rk, &dh_recv);
        self.state.root_key = new_rk;
        self.state.chain_key_recv = Some(ck_recv);

        // New Keypair - In production we gen random. In conformance we might need hook.
        // For now, assume standard random.
        // If we want deterministic, we need a trait or callback.
        // We will default to random and allow monkeypatching via internal flag/feature if needed?
        // Or cleaner: make `generate_encryption_keypair` pluggable?
        // For Rust, typically we pass a KeyProvider.
        let new_kp = crypto::x25519_generate();
        self.state.dh_keypair = KeyPair::from(new_kp);

        let dh_send = crypto::x25519_dh(
            array_ref(&self.state.dh_keypair.private_key),
            array_ref(self.state.dh_remote.as_ref().unwrap()),
        );
        let (new_rk_2, ck_send) = kdf_rk(&self.state.root_key, &dh_send);
        self.state.root_key = new_rk_2;
        self.state.chain_key_send = Some(ck_send);
    }

    fn initialize_sending_chain(&mut self) -> TalosResult<()> {
        self.state.prev_send_count = self.state.send_count;
        self.state.send_count = 0;

        let new_kp = crypto::x25519_generate();
        self.state.dh_keypair = KeyPair::from(new_kp);

        if let Some(remote) = &self.state.dh_remote {
            let dh_send = crypto::x25519_dh(
                array_ref(&self.state.dh_keypair.private_key),
                array_ref(remote),
            );
            let (new_rk, ck_send) = kdf_rk(&self.state.root_key, &dh_send);
            self.state.root_key = new_rk;
            self.state.chain_key_send = Some(ck_send);
        }
        Ok(())
    }
}

pub struct SessionManager {
    identity_key: KeyPair,
    signed_prekey: KeyPair,
    prekey_signature: Vec<u8>,
}

impl SessionManager {
    pub fn new(identity: KeyPair) -> Self {
        // Init a signed prekey
        let spk_x = crypto::x25519_generate();
        let spk = KeyPair::from(spk_x);
        let sig = crypto::ed25519_sign(&spk.public_key, array_ref(&identity.private_key));

        Self {
            identity_key: identity,
            signed_prekey: spk,
            prekey_signature: sig.to_vec(),
        }
    }

    // Conformance helper to inject SPK
    pub fn set_signed_prekey(&mut self, spk: KeyPair, sig: Vec<u8>) {
        self.signed_prekey = spk;
        self.prekey_signature = sig;
    }

    pub fn get_prekey_bundle(&self) -> PrekeyBundle {
        PrekeyBundle {
            identity_key: self.identity_key.public_key.clone(),
            signed_prekey: self.signed_prekey.public_key.clone(),
            prekey_signature: self.prekey_signature.clone(),
            one_time_prekey: None,
        }
    }

    pub fn create_initiator(&self, remote_bundle: &PrekeyBundle) -> TalosResult<Session> {
        // Verify signature
        let mut id_pub = [0u8; 32];
        if remote_bundle.identity_key.len() != 32 {
            return Err(TalosError::CryptoError("Invalid ID key".into()));
        }
        id_pub.copy_from_slice(&remote_bundle.identity_key);

        let mut spk_pub = [0u8; 32];
        if remote_bundle.signed_prekey.len() != 32 {
            return Err(TalosError::CryptoError("Invalid SPK".into()));
        }
        spk_pub.copy_from_slice(&remote_bundle.signed_prekey);

        let mut sig = [0u8; 64];
        if remote_bundle.prekey_signature.len() != 64 {
            return Err(TalosError::CryptoError("Invalid Sig".into()));
        }
        sig.copy_from_slice(&remote_bundle.prekey_signature);

        if !crypto::ed25519_verify(&remote_bundle.signed_prekey, &sig, &id_pub) {
            return Err(TalosError::CryptoError("Invalid prekey signature".into()));
        }

        let eph = crypto::x25519_generate();
        let dh_x3dh = crypto::x25519_dh(&eph.private, &spk_pub);
        let root_key = crypto::hkdf_derive(&dh_x3dh, b"x3dh-init", 32);

        let dh_out = crypto::x25519_dh(&eph.private, &spk_pub);
        let (rk, ck_send) = kdf_rk(&root_key, &dh_out);

        Ok(Session::new(RatchetState {
            dh_keypair: KeyPair::from(eph),
            dh_remote: Some(remote_bundle.signed_prekey.clone()),
            root_key: rk,
            chain_key_send: Some(ck_send),
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: Vec::new(),
        }))
    }

    pub fn create_responder(
        &self,
        remote_dh_public: &[u8],
        _remote_identity: &[u8],
    ) -> TalosResult<Session> {
        let mut rem_dh = [0u8; 32];
        if remote_dh_public.len() != 32 {
            return Err(TalosError::CryptoError("Invalid DH".into()));
        }
        rem_dh.copy_from_slice(remote_dh_public);

        let spk_priv = array_ref(&self.signed_prekey.private_key);
        let dh_x3dh = crypto::x25519_dh(spk_priv, &rem_dh);
        let root_key = crypto::hkdf_derive(&dh_x3dh, b"x3dh-init", 32);

        let dh_recv = crypto::x25519_dh(spk_priv, &rem_dh);
        let (rk, ck_recv) = kdf_rk(&root_key, &dh_recv);

        Ok(Session::new(RatchetState {
            dh_keypair: self.signed_prekey.clone(),
            dh_remote: Some(remote_dh_public.to_vec()),
            root_key: rk,
            chain_key_send: None,
            chain_key_recv: Some(ck_recv),
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: Vec::new(),
        }))
    }
}

// Key Derivation Helpers

fn kdf_rk(rk: &[u8], dh_out: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut input = Vec::new();
    input.extend_from_slice(rk);
    input.extend_from_slice(dh_out);
    let output = crypto::hkdf_derive(&input, INFO_ROOT, 64);
    (output[0..32].to_vec(), output[32..64].to_vec())
}

fn kdf_ck(ck: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mk = crypto::hkdf_derive(ck, INFO_MESSAGE, 32);
    let next_ck = crypto::hkdf_derive(ck, INFO_CHAIN, 32);
    (mk, next_ck)
}

fn array_ref(v: &[u8]) -> &[u8; 32] {
    v.try_into().expect("slice with incorrect length")
}

// Serde Helpers for Base64
mod base64_serde {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD.decode(s).map_err(serde::de::Error::custom)
    }
}

mod base64_serde_opt {
    use super::*;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(v) => serializer.serialize_str(&URL_SAFE_NO_PAD.encode(v)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: Option<String> = Option::deserialize(deserializer)?;
        match s {
            Some(text) => URL_SAFE_NO_PAD
                .decode(text)
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

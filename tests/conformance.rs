use serde_json::Value;
use std::fs;
use talos_core_rs::crypto;
use talos_core_rs::ratchet::{self, KeyPair, PrekeyBundle, Session, SessionManager};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

fn b64u_decode(s: &str) -> Vec<u8> {
    match URL_SAFE_NO_PAD.decode(s) {
        Ok(v) => v,
        Err(e) => panic!("base64 decode failed for '{}': {:?}", s, e),
    }
}

#[allow(dead_code)]
fn b64u_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn keypair_from_dict(d: &Value) -> KeyPair {
    KeyPair {
        public_key: b64u_decode(d["identity_public"].as_str().unwrap()),
        private_key: b64u_decode(d["identity_private"].as_str().unwrap()),
        key_type: "x25519".to_string(),
    }
}

struct RatchetHandler {
    alice_session: Option<Session>,
    bob_session: Option<Session>,
    bob_identity_public: Vec<u8>,
}

impl RatchetHandler {
    fn new() -> Self {
        Self {
            alice_session: None,
            bob_session: None,
            bob_identity_public: vec![],
        }
    }

    fn run_trace(&mut self, trace: &Value) -> Result<(), String> {
        let alice_id = keypair_from_dict(&trace["alice"]);
        let bob_id = keypair_from_dict(&trace["bob"]);

        let mut _alice_mgr = SessionManager::new(alice_id.clone());
        let mut bob_mgr = SessionManager::new(bob_id.clone());

        // Setup Bundle secrets for Bob (inject SPK)
        let bob_secrets = &trace["bob"]["bundle_secrets"];
        let spk_priv = b64u_decode(bob_secrets["signed_prekey_private"].as_str().unwrap());

        let _spk_pub = crypto::ed25519_public_key(&spk_priv.clone().try_into().unwrap());

        let spk_kp = KeyPair {
            public_key: b64u_decode(
                trace["bob"]["prekey_bundle"]["signed_prekey"]
                    .as_str()
                    .unwrap(),
            ),
            private_key: spk_priv,
            key_type: "x25519".to_string(),
        };
        let spk_sig = b64u_decode(
            trace["bob"]["prekey_bundle"]["prekey_signature"]
                .as_str()
                .unwrap(),
        );

        bob_mgr.set_signed_prekey(spk_kp, spk_sig);

        // Create Alice Session
        let alice_eph_priv = b64u_decode(trace["alice"]["ephemeral_private"].as_str().unwrap());

        let bundle_dict = &trace["bob"]["prekey_bundle"];
        let _bundle = PrekeyBundle {
            identity_key: b64u_decode(bundle_dict["identity_key"].as_str().unwrap()),
            signed_prekey: b64u_decode(bundle_dict["signed_prekey"].as_str().unwrap()),
            prekey_signature: b64u_decode(bundle_dict["prekey_signature"].as_str().unwrap()),
            one_time_prekey: None,
        };

        let _alice_eph_pub = crypto::x25519_generate().public;
        let mut alice_eph_priv_arr = [0u8; 32];
        alice_eph_priv_arr.copy_from_slice(&alice_eph_priv);
        let _alice_eph_pub_arr = crypto::x25519_dh(&alice_eph_priv_arr, &[9u8; 32]);

        let spk_pub = b64u_decode(bundle_dict["signed_prekey"].as_str().unwrap());
        let mut spk_pub_arr = [0u8; 32];
        spk_pub_arr.copy_from_slice(&spk_pub);

        let dh_val = crypto::x25519_dh(&alice_eph_priv_arr, &spk_pub_arr);
        let rk = crypto::hkdf_derive(&dh_val, b"x3dh-init", 32);

        let dh_out_val = dh_val;

        let (root_key, ck_send) = kdf_rk(&rk, &dh_out_val);

        let sc = x25519_dalek::StaticSecret::from(alice_eph_priv_arr);
        let pk = x25519_dalek::PublicKey::from(&sc);

        self.alice_session = Some(Session::new(ratchet::RatchetState {
            dh_keypair: KeyPair {
                public_key: pk.as_bytes().to_vec(),
                private_key: alice_eph_priv,
                key_type: "x25519".to_string(),
            },
            dh_remote: Some(spk_pub),
            root_key: root_key,
            chain_key_send: Some(ck_send),
            chain_key_recv: None,
            send_count: 0,
            recv_count: 0,
            prev_send_count: 0,
            skipped_keys: vec![],
        }));

        self.bob_session = None;
        self.bob_identity_public = bob_id.public_key;

        for step in trace["steps"].as_array().unwrap() {
            let actor = step["actor"].as_str().unwrap();
            let action = step["action"].as_str().unwrap();

            if action == "encrypt" {
                let pt = b64u_decode(step["plaintext"].as_str().unwrap());
                let _expected_ct = b64u_decode(step["ciphertext"].as_str().unwrap());

                let session = if actor == "alice" {
                    self.alice_session.as_mut()
                } else {
                    self.bob_session.as_mut()
                };

                if let Some(s) = session {
                    if let Some(priv_b64) = step.get("ratchet_priv") {
                        let _priv_bytes = b64u_decode(priv_b64.as_str().unwrap());
                    }

                    let out = s.encrypt(&pt).unwrap();
                    if actor == "alice" && step["step"].as_u64().unwrap() == 1 {
                        let h_len = u16::from_be_bytes([out[0], out[1]]) as usize;
                        let _ct_actual = &out[2 + h_len..];
                        let _ct_bytes = &out[2 + h_len + 12..];
                        let _nonce_bytes = &out[2 + h_len..2 + h_len + 12];
                    }
                }
            } else if action == "decrypt" {
                let ct_str = step["ciphertext"].as_str().unwrap();
                let nonce_str = step["nonce"].as_str().unwrap();
                let _header_obj = &step["header"];
                let _aad_str = step["aad"].as_str().unwrap();

                let header_bytes = b64u_decode(step["aad"].as_str().unwrap());
                let nonce_bytes = b64u_decode(nonce_str);
                let ct_bytes = b64u_decode(ct_str);

                let mut full_msg = Vec::new();
                let h_len = (header_bytes.len() as u16).to_be_bytes();
                full_msg.extend_from_slice(&h_len);
                full_msg.extend_from_slice(&header_bytes);
                full_msg.extend_from_slice(&nonce_bytes);
                full_msg.extend_from_slice(&ct_bytes);

                let expected_pt = b64u_decode(step["expected_plaintext"].as_str().unwrap());

                if actor == "bob" && self.bob_session.is_none() {
                    let h: Value = serde_json::from_slice(&header_bytes).unwrap();
                    let alice_dh = b64u_decode(h["dh"].as_str().unwrap());
                    let s = bob_mgr
                        .create_responder(&alice_dh, &[])
                        .expect("create responder failed");
                    self.bob_session = Some(s);
                }

                let session = if actor == "alice" {
                    self.alice_session.as_mut()
                } else {
                    self.bob_session.as_mut()
                };
                if let Some(s) = session {
                    match s.decrypt(&full_msg) {
                        Ok(pt) => {
                            assert_eq!(
                                pt, expected_pt,
                                "Plaintext mismatch at step {}",
                                step["step"]
                            );
                        }
                        Err(e) => {
                            if let Some(exp) = trace.get("expected_error") {
                                let msg_part = exp["message_contains"].as_str().unwrap();
                                if !format!("{:?}", e).contains(msg_part) {
                                    panic!("Expected error containing '{}', got {:?}", msg_part, e);
                                }
                            } else {
                                panic!("Decrypt failed at step {}: {:?}", step["step"], e);
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

#[test]
fn test_roundtrip_basic() {
    let content =
        fs::read_to_string("../talos-contracts/test_vectors/sdk/ratchet/roundtrip_basic.json")
            .expect("Failed to read vector");
    let trace: Value = serde_json::from_str(&content).unwrap();
    let mut handler = RatchetHandler::new();
    handler.run_trace(&trace).expect("Trace failed");
}

#[test]
fn test_out_of_order() {
    let content =
        fs::read_to_string("../talos-contracts/test_vectors/sdk/ratchet/out_of_order.json")
            .expect("Failed to read vector");
    let trace: Value = serde_json::from_str(&content).unwrap();
    let mut handler = RatchetHandler::new();
    handler.run_trace(&trace).expect("Trace failed");
}

#[test]
fn test_max_skip() {
    let content = fs::read_to_string("../talos-contracts/test_vectors/sdk/ratchet/max_skip.json")
        .expect("Failed to read vector");
    let trace: Value = serde_json::from_str(&content).unwrap();
    let mut handler = RatchetHandler::new();
    handler.run_trace(&trace).expect("Trace failed");
}

fn kdf_rk(rk: &[u8], dh_out: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut input = Vec::new();
    input.extend_from_slice(rk);
    input.extend_from_slice(dh_out);
    let output = crypto::hkdf_derive(&input, b"talos-double-ratchet-root", 64);
    (output[0..32].to_vec(), output[32..64].to_vec())
}

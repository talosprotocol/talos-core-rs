use talos_core_rs::adapters::crypto::RealCryptoProvider;
use talos_core_rs::domain::ratchet::SessionManager;
use talos_core_rs::domain::wallet::Wallet;
use talos_core_rs::encoding;
use talos_core_rs::ports::crypto::CryptoProvider;

#[test]
fn test_e2e_conversation() {
    let provider = RealCryptoProvider;

    // 1. Setup Identities
    let _alice_wallet = Wallet::generate(Some("Alice".into()), &provider);
    let _bob_wallet = Wallet::generate(Some("Bob".into()), &provider);

    // X25519 Identities (simulated from Ed25519 for now or generated separately)
    // The current implementation separates Wallet (Ed25519) from Ratchet (X25519).
    // In a real app, we'd sign the X25519 key with the Ed25519 key.
    // Here we just generate fresh X25519 identity keys for the ratchet session.

    let (alice_id_pub, alice_id_priv) = provider.x25519_generate();
    let (bob_id_pub, bob_id_priv) = provider.x25519_generate();

    let alice_mgr = SessionManager::new(alice_id_pub, alice_id_priv);
    let mut bob_mgr = SessionManager::new(bob_id_pub, bob_id_priv);

    // 2. Bob publishes a Prekey Bundle
    let bob_bundle = bob_mgr.get_prekey_bundle(&provider);

    // 3. Alice initiates session
    let mut alice_session = alice_mgr
        .create_initiator(&bob_bundle, &provider)
        .expect("Alice failed to create session");

    // 4. Alice sends message to Bob
    let msg1 = b"Hello Bob, this is Alice!";
    let encrypted_msg1 = alice_session
        .encrypt(msg1, &provider)
        .expect("Alice failed to encrypt");

    // 5. Bob receives message
    // Note: In real world, Bob needs to know WHICH session or create it from the header.
    // The header contains the public key used.
    // Here we manually extract potential public key to create responder session?
    // Or we assume we parse the header first.

    // We need to parse the header from `encrypted_msg1` to get the ephemeral key to init Bob.
    // `encrypted_msg1` format: [Len(4)][Header][Ciphertext]
    // Header contains `dh` (public key).

    let header_len = u32::from_be_bytes(encrypted_msg1[..4].try_into().unwrap()) as usize;
    let header_json = &encrypted_msg1[4..4 + header_len];
    let header: serde_json::Value = serde_json::from_slice(header_json).unwrap();

    // Get the ephemeral key Alice used
    let alice_ephemeral = if let Some(v) = header.get("public_key") {
        encoding::base64url_decode(v.as_str().unwrap()).unwrap()
    } else {
        // Fallback if renaming happened
        let val = header.get("dh").expect("Missing public key in header");
        // It might be a byte array in JSON if serialized default?
        // No, serde serializes [u8;32] as array of numbers by default unless we used hex/base64 wrapper.
        // Wait, `RatchetState` uses `[u8; 32]`. Serde default for `[u8; N]` is `[num, num, ...]`.
        // BUT `base64` crate usage implies we might want base64?
        // The previous code had `serde` derive.
        // Let's check `test_e2e` output if it fails.
        // If it sends array of integers, we need to parse it as such.
        println!("Header: {:?}", header);
        serde_json::from_value::<Vec<u8>>(val.clone()).unwrap_or_else(|_| {
            // If it's a string (base64) ???
            // The structs in `ratchet.rs` derive Serialize. Standard serde for `[u8; 32]` is sequence of ints.
            // UNLESS `serde_bytes` or custom serializer is used. `ratchet.rs` uses default derive.
            // So it will be a list of integers.
            serde_json::from_value::<Vec<u8>>(val.clone()).unwrap()
        })
    };

    let mut bob_session = bob_mgr
        .create_responder(&alice_ephemeral, &[], &provider)
        .expect("Bob failed to create responder session");

    let decrypted_msg1 = bob_session
        .decrypt(&encrypted_msg1, &provider)
        .expect("Bob failed to decrypt");

    assert_eq!(msg1.to_vec(), decrypted_msg1);
    println!(
        "Bob received: {:?}",
        String::from_utf8_lossy(&decrypted_msg1)
    );

    // 6. Bob replies to Alice
    let msg2 = b"Hi Alice! Loud and clear.";
    let encrypted_msg2 = bob_session
        .encrypt(msg2, &provider)
        .expect("Bob failed to encrypt");

    // 7. Alice receives reply
    // Alice already has session open.
    let decrypted_msg2 = alice_session
        .decrypt(&encrypted_msg2, &provider)
        .expect("Alice failed to decrypt");

    assert_eq!(msg2.to_vec(), decrypted_msg2);
    println!(
        "Alice received: {:?}",
        String::from_utf8_lossy(&decrypted_msg2)
    );
}

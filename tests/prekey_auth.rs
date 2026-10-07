use talos_core_rs::adapters::crypto::RealCryptoProvider;
use talos_core_rs::domain::ratchet::{PrekeyBundle, SessionManager};
use talos_core_rs::domain::wallet::Wallet;
use talos_core_rs::ports::crypto::CryptoProvider;

#[test]
fn generated_prekey_bundle_has_a_valid_identity_signature() {
    let provider = RealCryptoProvider;
    let identity = Wallet::from_seed([7; 32], None, &provider);
    let mut manager = SessionManager::new(identity.public_key, identity.secret_key);

    let bundle = manager.get_prekey_bundle(&provider).unwrap();
    let signature: [u8; 64] = bundle.prekey_signature.as_slice().try_into().unwrap();

    assert!(provider.ed25519_verify(&bundle.signed_prekey, &signature, &bundle.identity_key));

    let repeated = manager.get_prekey_bundle(&provider).unwrap();
    assert_eq!(bundle.signed_prekey, repeated.signed_prekey);
    assert_eq!(bundle.prekey_signature, repeated.prekey_signature);
}

#[test]
fn generated_bundle_fails_closed_for_mismatched_identity_keys() {
    let provider = RealCryptoProvider;
    let identity = Wallet::from_seed([7; 32], None, &provider);
    let other_identity = Wallet::from_seed([8; 32], None, &provider);
    let mut manager = SessionManager::new(other_identity.public_key, identity.secret_key);

    assert!(manager.get_prekey_bundle(&provider).is_err());
}

#[test]
fn initiator_rejects_modified_and_missing_prekey_signatures() {
    let provider = RealCryptoProvider;
    let alice = Wallet::from_seed([1; 32], None, &provider);
    let bob = Wallet::from_seed([2; 32], None, &provider);
    let alice_manager = SessionManager::new(alice.public_key, alice.secret_key);
    let mut bob_manager = SessionManager::new(bob.public_key, bob.secret_key);
    let valid = bob_manager.get_prekey_bundle(&provider).unwrap();

    let mut modified = valid.clone();
    modified.signed_prekey[0] ^= 1;
    assert!(alice_manager
        .create_initiator(&modified, &provider)
        .is_err());

    let mut missing = valid;
    missing.prekey_signature.clear();
    assert!(alice_manager.create_initiator(&missing, &provider).is_err());
}

#[test]
fn injected_prekey_requires_a_valid_identity_signature() {
    let provider = RealCryptoProvider;
    let identity = Wallet::from_seed([3; 32], None, &provider);
    let mut manager = SessionManager::new(identity.public_key, identity.secret_key);
    let (spk_public, spk_private) = provider.x25519_generate();

    assert!(manager
        .set_signed_prekey(spk_public, spk_private, vec![0; 64], &provider)
        .is_err());
    assert!(manager.get_prekey_bundle(&provider).is_ok());
}

#[test]
fn injected_prekey_bundle_preserves_its_verified_signature() {
    let provider = RealCryptoProvider;
    let identity = Wallet::from_seed([4; 32], None, &provider);
    let mut manager = SessionManager::new(identity.public_key, identity.secret_key);
    let (spk_public, spk_private) = provider.x25519_generate();
    let signature = provider.ed25519_sign(&spk_public, &identity.secret_key);

    manager
        .set_signed_prekey(spk_public, spk_private, signature.to_vec(), &provider)
        .unwrap();
    let bundle = manager.get_prekey_bundle(&provider).unwrap();
    assert_eq!(bundle.prekey_signature, signature.to_vec());

    let mut tampered = PrekeyBundle {
        identity_key: bundle.identity_key,
        signed_prekey: bundle.signed_prekey,
        prekey_signature: bundle.prekey_signature,
        one_time_prekey: None,
    };
    tampered.identity_key[0] ^= 1;
    assert!(manager.create_initiator(&tampered, &provider).is_err());
}

use hex;
use talos_core_rs::adapters::crypto::RealCryptoProvider;
use talos_core_rs::ports::crypto::CryptoProvider;

#[test]
fn test_hmac_sha256_vector() {
    let provider = RealCryptoProvider;

    // RFC 4231 Test Case 2
    let key = b"Jefe";
    let data = b"what do ya want for nothing?";

    let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

    let result = provider.hmac_sha256(key, data);
    assert_eq!(hex::encode(result), expected);
}

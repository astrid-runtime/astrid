#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use astrid_crypto::{ContentHash, KeyPair, PublicKey, Signature};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Input {
    secret: [u8; 32],
    public_key: [u8; 32],
    signature: [u8; 64],
    message: Vec<u8>,
    other_message: Vec<u8>,
    text: String,
    bytes: Vec<u8>,
}

fuzz_target!(|data: &[u8]| {
    let mut data = Unstructured::new(data);
    let Ok(input) = Input::arbitrary(&mut data) else {
        return;
    };

    let hash = ContentHash::hash(&input.bytes);
    assert_eq!(ContentHash::from_hex(&hash.to_hex()).unwrap(), hash);
    assert_eq!(ContentHash::from_base64(&hash.to_base64()).unwrap(), hash);
    assert_eq!(ContentHash::try_from_slice(hash.as_bytes()), Some(hash));
    assert_eq!(
        ContentHash::try_from_slice(&input.bytes).is_some(),
        input.bytes.len() == 32
    );
    let _ = ContentHash::from_hex(&input.text);
    let _ = ContentHash::from_base64(&input.text);

    let public_key = PublicKey::from_bytes(input.public_key);
    assert_eq!(
        PublicKey::from_hex(&public_key.to_hex()).unwrap(),
        public_key
    );
    assert_eq!(
        PublicKey::from_base64(&public_key.to_base64()).unwrap(),
        public_key
    );
    assert_eq!(
        PublicKey::try_from_slice(&input.bytes).is_ok(),
        input.bytes.len() == 32
    );
    let _ = PublicKey::from_hex(&input.text);
    let _ = PublicKey::from_base64(&input.text);

    let signature = Signature::from_bytes(input.signature);
    assert_eq!(Signature::from_hex(&signature.to_hex()).unwrap(), signature);
    assert_eq!(
        Signature::from_base64(&signature.to_base64()).unwrap(),
        signature
    );
    assert_eq!(
        Signature::try_from_slice(&input.bytes).is_ok(),
        input.bytes.len() == 64
    );
    let _ = Signature::from_hex(&input.text);
    let _ = Signature::from_base64(&input.text);
    let _ = public_key.verify(&input.message, &signature);

    let keypair = KeyPair::from_secret_key(&input.secret).unwrap();
    let signed = keypair.sign(&input.message);
    assert!(keypair.verify(&input.message, &signed).is_ok());
    assert!(
        keypair
            .export_public_key()
            .verify(&input.message, &signed)
            .is_ok()
    );
    if input.other_message != input.message {
        assert!(keypair.verify(&input.other_message, &signed).is_err());
    }
});

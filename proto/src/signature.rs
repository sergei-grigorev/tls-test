use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use rand::RngCore;
use signature::Verifier;

// re-export the signature type
pub use ed25519_dalek::Signature;
pub use ed25519_dalek::SigningKey;
pub use ed25519_dalek::VerifyingKey;

/// Create a new key.
pub fn make_new_key() -> SigningKey {
    let mut csprng = OsRng;
    let signing_key: SigningKey = SigningKey::generate(&mut csprng);
    signing_key
}

pub fn new_challenge() -> Vec<u8> {
    let mut challenge = [0u8; 128];
    OsRng.fill_bytes(&mut challenge);
    challenge.to_vec()
}

pub fn new_key_id() -> u32 {
    OsRng.next_u32()
}

pub fn encode_public_key(key: &VerifyingKey) -> Vec<u8> {
    bincode::serialize(key).unwrap()
}

pub fn decode_public_key(bytes: &[u8]) -> Result<VerifyingKey, String> {
    bincode::deserialize(bytes).map_err(|_| "Key cannot be decoded".into())
}

pub fn sign_challenge(key: &SigningKey, challenge: &[u8]) -> Signature {
    key.sign(challenge)
}

pub fn validate_signature(key: &VerifyingKey, challenge: &[u8], signature: &Signature) -> bool {
    key.verify(challenge, &signature).is_ok()
}

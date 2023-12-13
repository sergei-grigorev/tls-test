use ed25519_dalek::Signer;
use rand::rngs::OsRng;
use rand::RngCore;
use signature::Verifier;

// re-export the signature type
pub use ed25519_dalek::Signature;
pub use ed25519_dalek::SigningKey;
pub use ed25519_dalek::VerifyingKey;
pub use ed25519_dalek::PUBLIC_KEY_LENGTH;
pub use ed25519_dalek::SIGNATURE_LENGTH;

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

pub fn sign_challenge(key: &SigningKey, challenge: &[u8]) -> Signature {
    key.sign(challenge)
}

pub fn validate_signature(key: &VerifyingKey, challenge: &[u8], signature: &Signature) -> bool {
    key.verify(challenge, &signature).is_ok()
}

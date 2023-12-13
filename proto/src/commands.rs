use crate::signature;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Command {
    NewUserBegin {
        username: String,
    },
    CertRequest {
        server: String,
        challenge: Vec<u8>,
    },
    CertResponse {
        credential_id: String,
        signed_challenge: signature::Signature,
        // somehow store here verifying key makes it's non properly serialized
        pub_certificate: Vec<u8>,
    },
    AuthBegin {
        username: String,
    },
    ChallengeRequest {
        credential_id: String,
        challenge: Vec<u8>,
    },
    ChallengeResponse {
        signed_challenge: signature::Signature,
        credential_id: String,
    },
    TextMessage(String),
    None,
}

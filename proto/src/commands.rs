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
        signed_challenge: Vec<u8>,
        credential_id: String,
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
        signed_challenge: Vec<u8>,
        credential_id: String,
    },
    TextMessage(String),
    None,
}

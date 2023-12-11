use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub enum Command {
    NewUserBegin {
        username: String,
    },
    CertRequest {
        server: String,
        challenge: String,
    },
    CertResponse {
        signed_challenge: String,
        credential_id: String,
        pub_certificate: String,
    },
    AuthBegin {
        username: String,
    },
    ChallengeRequest {
        credential_id: String,
        challenge: String,
    },
    ChallengeResponse {
        signed_challenge: String,
        credential_id: String,
    },
    TextMessage(String),
		None
}

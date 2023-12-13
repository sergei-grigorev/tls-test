use std::{env, fs::File, io::Read, net::TcpListener, sync::Arc, thread};

use native_tls::{Identity, TlsAcceptor};
use proto::connection::TlsStreamExt;
use proto::signature;
use proto::{commands::Command, connection::Connection};

fn main() {
    // print current directory
    let current_path = env::current_dir().unwrap();
    let current_path = current_path.as_path().to_str().unwrap_or_default();

    println!("Current dir: [{}]", current_path);
    let certificate_file = format!("{current_path}/certs/server_identity.pfx");
    println!("Certificate file: [{}]", certificate_file);

    // load server certificate
    let mut file = File::open(certificate_file).expect("Server certificate is not found");
    let mut identify = Vec::new();
    file.read_to_end(&mut identify)
        .expect("Problem reading the server certificate");

    let identity = Identity::from_pkcs12(&identify, "my_server_password")
        .expect("Certificate is corrupted or the password is incorrect");

    let listener = TcpListener::bind("127.0.0.1:8443").unwrap();
    let acceptor = TlsAcceptor::builder(identity)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv12))
        .build()
        .unwrap();
    let acceptor = Arc::new(acceptor);

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let acceptor = acceptor.clone();
                thread::spawn(move || {
                    // run TLS
                    match acceptor.accept(stream) {
                        Ok(stream) => {
                            let stream = Connection::new(stream);
                            if let Err(e) = handle_client(stream) {
                                eprintln!("Error: {e}");
                            }
                        }
                        Err(e) => {
                            eprintln!("Connection error: {}", e.to_string());
                        }
                    }
                });
            }
            Err(e) => eprintln!("Connection failed: {}", e.to_string()),
        }
    }
}

fn handle_client(mut stream: Connection) -> Result<(), String> {
    // 1. wait a new user registration
    let session_username: String;
    let session_key: signature::VerifyingKey;
    let session_credential_id: String;
    if let Command::NewUserBegin { username } = stream.deserialize()? {
        session_username = username;

        // 2. send a new challenge
        let challenge = signature::new_challenge();
        stream.serialize(Command::CertRequest {
            server: "localhost".to_owned(),
            challenge: challenge.clone(),
        })?;

        // 3. receive a new public key
        if let Command::CertResponse {
            signed_challenge,
            credential_id,
            pub_certificate,
        } = stream.deserialize()?
        {
            // validate the length
            if signed_challenge.len() != signature::SIGNATURE_LENGTH
                || pub_certificate.len() != signature::PUBLIC_KEY_LENGTH
            {
                return Err("Signature is incorrect".into());
            }

            let mut connection_key = [0u8; signature::PUBLIC_KEY_LENGTH];
            connection_key.copy_from_slice(&pub_certificate);

            session_key = signature::VerifyingKey::from_bytes(&connection_key)
                .map_err(|e| format!("Public key is broken: {}", e.to_string()))?;

            let mut signature = [0u8; signature::SIGNATURE_LENGTH];
            signature.copy_from_slice(&signed_challenge);

            let signature = signature::Signature::from_bytes(&signature);

            if !signature::validate_signature(&session_key, &challenge, &signature) {
                return Err("Signature is not correct".into());
            }

            // SUCCESS
            session_credential_id = credential_id;
            eprintln!("Registered new key {session_credential_id}");
        } else {
            return Err("Incorrect certificate response message".into());
        }
    } else {
        return Err("Incorrect first message".into());
    }

    // 4. wait user auth message
    if let Command::AuthBegin { username } = stream.deserialize()? {
        if username != session_username {
            return Err("Unknown user".into());
        }

        // 5. send a new challenge
        let auth_challenge = signature::new_challenge();
        stream.serialize(Command::ChallengeRequest {
            credential_id: session_credential_id.clone(),
            challenge: auth_challenge.clone(),
        })?;

        // 6. validate the signature
        if let Command::ChallengeResponse {
            signed_challenge,
            credential_id,
        } = stream.deserialize()?
        {
            if credential_id != session_credential_id {
                return Err("Incorrect credential_id returned".into());
            }

            if signed_challenge.len() != signature::SIGNATURE_LENGTH {
                return Err("Broken signature".into());
            }

            // let mut signature = [0u8; signature::SIGNATURE_LENGTH];
            let mut signature = [0u8; signature::SIGNATURE_LENGTH];
            signature.copy_from_slice(&signed_challenge);
            let signature = signature::Signature::from_bytes(&signature);

            if !signature::validate_signature(&session_key, &auth_challenge, &signature) {
                return Err("Signature is not correct".into());
            }

            // SUCCESS
        } else {
            return Err("Incorrect message, expected challenge response".into());
        }
    }

    // send a welcome message
    stream.serialize(Command::TextMessage("Hello from server".into()))?;

    // wait a client message
    let command: Command = stream.deserialize()?;

    // convert to just a text
    let full_message: String = if let Command::TextMessage(line) = command {
        line
    } else {
        format!("Unknown message: {:?}", command)
    };

    println!("{}", full_message);
    Ok(())
}

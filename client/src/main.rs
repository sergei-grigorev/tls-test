use std::sync::Arc;
use std::{env, fs::File, io::Read, net::TcpStream};

use rustls::pki_types::CertificateDer;
// use native_tls::{Certificate, TlsConnector};
use proto::commands::Command;
use proto::connection::{Connection, RustTls, TlsStreamExt};
use proto::signature;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

fn main() {
    // print current directory
    let current_path = env::current_dir().unwrap();
    let current_path = current_path.as_path().to_str().unwrap_or_default();

    println!("Current dir: [{}]", current_path);
    let ca_cert_file = format!("{current_path}/certs/ca.der");
    println!("CA file: [{}]", ca_cert_file);
    // let client_cert_file = format!("{current_path}/certs/client_identity.pfx");
    // println!("Client identity file: [{}]", ca_cert_file);

    // load CA certificate
    let mut file = File::open(ca_cert_file).expect("Server certificate is not found");
    let mut ca_certificate = Vec::new();
    file.read_to_end(&mut ca_certificate)
        .expect("Problem reading the server certificate");
    let ca_certificate = CertificateDer::from(ca_certificate);

    let mut ca_root = RootCertStore::empty();
    ca_root
        .add(ca_certificate)
        .expect("Problem with loading root certificate");

    // load client certificate
    // let mut file = File::open(client_cert_file).expect("Client certificate is not found");
    // let mut identify = Vec::new();
    // file.read_to_end(&mut identify)
    //     .expect("Problem reading the server certificate");

    // let identity = Identity::from_pkcs12(&identify, "my_client_password")
    //     .expect("Certificate is corrupted or the password is incorrect");

    let config = ClientConfig::builder()
        .with_root_certificates(ca_root)
        .with_no_client_auth();

    let arc_config = Arc::new(config);
    let server_name = "localhost".try_into().unwrap();
    let client = ClientConnection::new(arc_config, server_name)
        .unwrap()
        .into();

    let socket = TcpStream::connect("127.0.0.1:8443").unwrap();
    let stream = Connection::<RustTls>::new(client, socket);

    if let Err(e) = handle_connection(stream) {
        eprintln!("Error: {e}");
    }
}

fn handle_connection(mut stream: Connection<RustTls>) -> Result<(), String> {
    // 1. start a new user registration
    let user_name = "sergei";
    stream.serialize(Command::NewUserBegin {
        username: user_name.to_owned(),
    })?;
    println!("Requested a new user registration");

    // 2. receive a new challenge
    let private_key: signature::SigningKey;
    let key_id: String = signature::new_key_id().to_string();
    if let Command::CertRequest {
        server: _,
        challenge,
    } = stream.deserialize()?
    {
        // 3. create a new key and send to the server
        let key = signature::make_new_key();
        let signature = signature::sign_challenge(&key, &challenge);

        stream.serialize(Command::CertResponse {
            signed_challenge: signature,
            credential_id: key_id.clone(),
            pub_certificate: signature::encode_public_key(&key.verifying_key()),
        })?;

        private_key = key;
    } else {
        return Err("Server should have send a new cert request".into());
    }

    println!("User has been registered");

    // 4. try to auth
    stream.serialize(Command::AuthBegin {
        username: user_name.to_owned(),
    })?;

    // 5. receive a challenge
    if let Command::ChallengeRequest {
        credential_id,
        challenge,
    } = stream.deserialize()?
    {
        // validate that there is no errors
        if credential_id != key_id {
            return Err("Server requested wrong key".into());
        }

        let signature = signature::sign_challenge(&private_key, &challenge);

        stream.serialize(Command::ChallengeResponse {
            signed_challenge: signature,
            credential_id: credential_id,
        })?;
    } else {
        return Err("Server should have send an auth challenge".into());
    }

    // 6. wait a server message
    let command: Command = stream.deserialize()?;

    // send a welcome message
    stream.serialize(Command::TextMessage(format!("Hello from [{}]", user_name)))?;

    // convert to just a text
    let full_message: String = if let Command::TextMessage(line) = command {
        line
    } else {
        format!("Unknown message: {:?}", command)
    };

    println!("{}", full_message);
    Ok(())
}

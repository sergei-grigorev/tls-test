use std::{env, fs::File, io::Read, net::TcpStream};

use native_tls::{Certificate, Identity, TlsConnector};
use proto::commands::Command;
use proto::connection::{Connection, TlsStreamExt};

fn main() {
    // print current directory
    let current_path = env::current_dir().unwrap();
    let current_path = current_path.as_path().to_str().unwrap_or_default();

    println!("Current dir: [{}]", current_path);
    let ca_cert_file = format!("{current_path}/certs/ca.crt");
    println!("CA file: [{}]", ca_cert_file);
    let client_cert_file = format!("{current_path}/certs/client_identity.pfx");
    println!("Client identity file: [{}]", ca_cert_file);

    // load CA certificate
    let mut file = File::open(ca_cert_file).expect("Server certificate is not found");
    let mut ca_certificate = Vec::new();
    file.read_to_end(&mut ca_certificate)
        .expect("Problem reading the server certificate");

    let ca_certificate = Certificate::from_pem(&ca_certificate).expect("Certificate is corrupted");

    // load client certificate
    let mut file = File::open(client_cert_file).expect("Client certificate is not found");
    let mut identify = Vec::new();
    file.read_to_end(&mut identify)
        .expect("Problem reading the server certificate");

    let identity = Identity::from_pkcs12(&identify, "my_client_password")
        .expect("Certificate is corrupted or the password is incorrect");

    let connector = TlsConnector::builder()
        .disable_built_in_roots(true)
        .add_root_certificate(ca_certificate)
        .identity(identity)
        .build()
        .unwrap();

    let stream = TcpStream::connect("127.0.0.1:8443").unwrap();
    let stream = connector.connect("localhost", stream).unwrap();
    let stream = Connection::new(stream);

    if let Err(e) = handle_connection(stream) {
        eprintln!("Error: {e}");
    }
}

fn handle_connection(mut stream: Connection) -> Result<(), String> {
    // wait a server message
    let command: Command = stream.deserialize()?;

    // send a welcome message
    stream.serialize(Command::TextMessage("Hello from client".into()))?;

    // convert to just a text
    let full_message: String = if let Command::TextMessage(line) = command {
        line
    } else {
        format!("Unknown message: {:?}", command)
    };

    println!("{}", full_message);
    Ok(())
}

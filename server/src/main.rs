use std::{env, fs::File, io::Read, net::TcpListener, sync::Arc, thread};

use native_tls::{Identity, TlsAcceptor};
use proto::connection::TlsStreamExt;
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

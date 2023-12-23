use std::net::TcpStream;

use crate::commands::Command;

use super::{
    io::{deserialize, serialize},
    mut_buf::MutBuf,
    Connection, TlsStreamExt,
};

pub struct RustTls {
    stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
}

impl Connection<RustTls> {
    pub fn new(connection: rustls::ClientConnection, socket: TcpStream) -> Self {
        Self {
            connection: RustTls {
                stream: rustls::StreamOwned {
                    conn: connection,
                    sock: socket,
                },
            },
            buf: MutBuf::new(4096),
        }
    }
}

impl TlsStreamExt for Connection<RustTls> {
    fn serialize(&mut self, message: Command) -> Result<(), String> {
        serialize(&mut self.connection.stream, message)
    }

    fn deserialize(&mut self) -> Result<Command, String> {
        deserialize(&mut self.connection.stream, &mut self.buf)
    }
}

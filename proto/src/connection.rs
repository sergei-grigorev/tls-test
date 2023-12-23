use std::net::TcpStream;

use crate::commands::Command;

use self::{
    io::{deserialize, serialize},
    mut_buf::MutBuf,
};

mod io;
mod mut_buf;

#[cfg(feature = "native-tls")]
pub struct NativeTls {
    stream: native_tls::TlsStream<TcpStream>,
}

#[cfg(feature = "rust-tls")]
pub struct RustTls {
    stream: rustls::StreamOwned<rustls::ClientConnection, TcpStream>,
}

pub struct Connection<S> {
    connection: S,
    buf: MutBuf,
}

#[cfg(feature = "native-tls")]
impl Connection<NativeTls> {
    pub fn new(stream: native_tls::TlsStream<TcpStream>) -> Self {
        Self {
            connection: NativeTls { stream },
            // Allocate the buffer with 4kb of capacity.
            buf: MutBuf::new(4096),
        }
    }
}

#[cfg(feature = "rust-tls")]
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

pub trait TlsStreamExt {
    fn serialize(&mut self, message: Command) -> Result<(), String>;
    fn deserialize(&mut self) -> Result<Command, String>;
}

#[cfg(feature = "native-tls")]
impl TlsStreamExt for Connection<NativeTls> {
    fn serialize(&mut self, message: Command) -> Result<(), String> {
        serialize(&mut self.connection.stream, message)
    }

    fn deserialize(&mut self) -> Result<Command, String> {
        deserialize(&mut self.connection.stream, &mut self.buf)
    }
}

#[cfg(feature = "rust-tls")]
impl TlsStreamExt for Connection<RustTls> {
    fn serialize(&mut self, message: Command) -> Result<(), String> {
        serialize(&mut self.connection.stream, message)
    }

    fn deserialize(&mut self) -> Result<Command, String> {
        deserialize(&mut self.connection.stream, &mut self.buf)
    }
}

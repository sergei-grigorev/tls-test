use std::net::TcpStream;

use crate::commands::Command;

use super::{
    io::{deserialize, serialize},
    mut_buf::MutBuf,
    Connection, TlsStreamExt,
};

pub struct NativeTls {
    stream: native_tls::TlsStream<TcpStream>,
}
impl Connection<NativeTls> {
    pub fn new(stream: native_tls::TlsStream<TcpStream>) -> Self {
        Self {
            connection: NativeTls { stream },
            // Allocate the buffer with 4kb of capacity.
            buf: MutBuf::new(4096),
        }
    }
}
impl TlsStreamExt for Connection<NativeTls> {
    fn serialize(&mut self, message: Command) -> Result<(), String> {
        serialize(&mut self.connection.stream, message)
    }

    fn deserialize(&mut self) -> Result<Command, String> {
        deserialize(&mut self.connection.stream, &mut self.buf)
    }
}

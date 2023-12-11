use std::{
    io::Read,
    io::{Cursor, Write},
    net::TcpStream,
};

use bincode::ErrorKind;
use native_tls::TlsStream;

use crate::commands::Command;

struct MutBuf {
    buffer: Vec<u8>,
    cursor: usize,
}

impl MutBuf {
    fn new(len: usize) -> Self {
        let mut buffer = Vec::with_capacity(len);
        buffer.resize(len, 0);
        Self { buffer, cursor: 0 }
    }

    fn discard(&mut self, len: usize) {
        self.buffer.drain(0..len);
        self.cursor -= len;
    }

    fn is_empty(&self) -> bool {
        self.cursor == 0
    }

    fn consumable(&self) -> &[u8] {
        &self.buffer[..self.cursor]
    }

    fn writable(&mut self) -> &mut [u8] {
        &mut self.buffer[self.cursor..]
    }

    fn add_consumable(&mut self, len: usize) {
        self.cursor += len;

        if self.cursor == self.buffer.len() {
            self.buffer.resize(self.cursor * 2, 0);
        }
    }

    fn parse_frame(&mut self) -> Result<Option<Command>, String> {
        let mut buf = Cursor::new(self.consumable());

        match bincode::deserialize_from(&mut buf) {
            Ok(command) => {
                // get the position in the cursor
                let len = buf.position() as usize;

                // Discard the frame from the buffer
                self.discard(len);

                Ok(Some(command))
            }
            Err(e) => match e.as_ref() {
                ErrorKind::Io(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
                other => Err(other.to_string()),
            },
        }
    }
}

pub struct Connection {
    stream: TlsStream<TcpStream>,
    buf: MutBuf,
}

impl Connection {
    pub fn new(stream: TlsStream<TcpStream>) -> Self {
        Self {
            stream,
            // Allocate the buffer with 4kb of capacity.
            buf: MutBuf::new(4096),
        }
    }
}

pub trait TlsStreamExt {
    fn serialize(&mut self, message: Command) -> Result<(), String>;
    fn deserialize(&mut self) -> Result<Command, String>;
}

impl TlsStreamExt for Connection {
    fn serialize(&mut self, message: Command) -> Result<(), String> {
        let buffer = bincode::serialize(&message).unwrap();
        self.stream
            .write_all(&buffer)
            .map_err(|e| format!("IO write error: {}", e.to_string()))
    }

    fn deserialize(&mut self) -> Result<Command, String> {
        loop {
            // try to parse
            if let Some(message) = self
                .buf
                .parse_frame()
                .map_err(|e| format!("Parse error: {e}"))?
            {
                return Ok(message);
            }

            // read to the buffer otherwise
            let n = self
                .stream
                .read(self.buf.writable())
                .map_err(|e| format!("IO read error: {}", e.to_string()))?;

            // if read returns 0 then the connection is closed (properly)
            if 0 == n {
                if self.buf.is_empty() {
                    return Ok(Command::None);
                } else {
                    return Err("connection reset by peer".into());
                }
            } else {
                self.buf.add_consumable(n);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{commands::Command, connection::MutBuf};

    #[test]
    fn multiple_messages_in_buffer() {
        let command1 = Command::TextMessage("Command 1".into());
        let command2 = Command::TextMessage("Command 2".into());

        let buf1 = bincode::serialize(&command1).unwrap();
        let buf2 = bincode::serialize(&command2).unwrap();

        // create a buffer
        let mut mut_buf = MutBuf::new(buf1.len() + buf2.len());
        assert_eq!(mut_buf.buffer.len(), buf1.len() + buf2.len());

        // write element 1
        mut_buf.writable()[..buf1.len()].copy_from_slice(&buf1);
        mut_buf.add_consumable(buf1.len());
        assert_eq!(mut_buf.cursor, buf1.len());

        // write element 2
        mut_buf.writable()[..buf2.len()].copy_from_slice(&buf2);
        mut_buf.add_consumable(buf1.len());
        assert_eq!(mut_buf.cursor, buf1.len() + buf2.len());

        // validate
        let parsed_command1 = mut_buf
            .parse_frame()
            .unwrap()
            .expect("First command is empty");
        let parsed_command2 = mut_buf
            .parse_frame()
            .unwrap()
            .expect("Second command is empty");

        assert_eq!(parsed_command1, command1);
        eprintln!(
            "Buffer size: {}, position: {}",
            mut_buf.buffer.len(),
            mut_buf.cursor
        );

        assert_eq!(parsed_command2, command2);
        eprintln!(
            "Buffer size: {}, position: {}",
            mut_buf.buffer.len(),
            mut_buf.cursor
        );

        // should be empty
        assert_eq!(true, mut_buf.is_empty());
    }
}

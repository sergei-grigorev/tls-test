use std::io::Cursor;

use bincode::ErrorKind;

use crate::commands::Command;

pub struct MutBuf {
    buffer: Vec<u8>,
    cursor: usize,
}

impl MutBuf {
    pub fn new(len: usize) -> Self {
        let buffer = vec![0u8; len];
        Self { buffer, cursor: 0 }
    }

    pub fn discard(&mut self, len: usize) {
        self.buffer.drain(0..len);
        self.cursor -= len;
    }

    pub fn is_empty(&self) -> bool {
        self.cursor == 0
    }

    pub fn consumable(&self) -> &[u8] {
        &self.buffer[..self.cursor]
    }

    pub fn writable(&mut self) -> &mut [u8] {
        &mut self.buffer[self.cursor..]
    }

    pub fn add_consumable(&mut self, len: usize) {
        self.cursor += len;

        if self.cursor == self.buffer.len() {
            self.buffer.resize(self.cursor * 2, 0);
        }
    }

    pub fn parse_frame(&mut self) -> Result<Option<Command>, String> {
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

#[cfg(test)]
mod tests {
    use super::MutBuf;
    use crate::commands::Command;

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

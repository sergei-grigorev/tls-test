use std::io::{Read, Write};

use crate::commands::Command;

use super::mut_buf::MutBuf;

pub fn serialize<S: Write>(stream: &mut S, message: Command) -> Result<(), String> {
    let buffer = bincode::serialize(&message).unwrap();
    stream
        .write_all(&buffer)
        .map_err(|e| format!("IO write error: {}", e))
}

pub fn deserialize<S: Read>(stream: &mut S, buf: &mut MutBuf) -> Result<Command, String> {
    loop {
        // try to parse
        if let Some(message) = buf.parse_frame().map_err(|e| format!("Parse error: {e}"))? {
            return Ok(message);
        }

        // read to the buffer otherwise
        let n = stream
            .read(buf.writable())
            .map_err(|e| format!("IO read error: {}", e))?;

        // if read returns 0 then the connection is closed (properly)
        if 0 == n {
            if buf.is_empty() {
                return Ok(Command::None);
            } else {
                return Err("connection reset by peer".into());
            }
        } else {
            buf.add_consumable(n);
        }
    }
}

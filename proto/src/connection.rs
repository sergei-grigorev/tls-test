use crate::commands::Command;

use self::mut_buf::MutBuf;

mod io;
mod mut_buf;

#[cfg(feature = "native-tls")]
mod native_tls;
#[cfg(feature = "native-tls")]
pub use native_tls::NativeTls;

#[cfg(feature = "rust-tls")]
mod rust_tls;
#[cfg(feature = "rust-tls")]
pub use rust_tls::RustTls;

pub struct Connection<S> {
    connection: S,
    buf: MutBuf,
}

pub trait TlsStreamExt {
    fn serialize(&mut self, message: Command) -> Result<(), String>;
    fn deserialize(&mut self) -> Result<Command, String>;
}

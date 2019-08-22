use bytes::Bytes;

use failure::Fail;
use openssl::error::ErrorStack;

pub use aes::*;
pub use plain::*;

mod aes;
mod plain;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Fail)]
pub enum EncryptError {
    #[fail(display = "OpenSSL Error")]
    OpenSsl(ErrorStack),
}

impl From<ErrorStack> for EncryptError {
    fn from(v: ErrorStack) -> Self {
        Self::OpenSsl(v)
    }
}

#[allow(clippy::module_name_repetitions)]
pub type EncryptResult<T> = Result<T, EncryptError>;

pub trait Encrypt {
    fn name(&self) -> &'static str;
    fn block_size(&self) -> usize;
    fn encrypt(&mut self, pkt: &Bytes) -> EncryptResult<Bytes>;
}

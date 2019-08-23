use bytes::Bytes;

use failure::Fail;
use openssl::error::ErrorStack;

pub(crate) use aes::*;
pub(crate) use plain::*;

mod aes;
mod plain;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Fail)]
pub(crate) enum EncryptError {
    #[fail(display = "OpenSSL Error")]
    OpenSsl(ErrorStack),
}

impl From<ErrorStack> for EncryptError {
    fn from(v: ErrorStack) -> Self {
        Self::OpenSsl(v)
    }
}

#[allow(clippy::module_name_repetitions)]
pub(crate) type EncryptResult<T> = Result<T, EncryptError>;

pub(crate) trait Encrypt {
    fn name(&self) -> &'static str;
    fn block_size(&self) -> usize;
    fn encrypt(&mut self, pkt: &Bytes) -> EncryptResult<Bytes>;
}

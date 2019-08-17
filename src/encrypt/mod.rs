use bytes::Bytes;

pub use aes::*;
pub use plain::*;

mod aes;
mod plain;

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum EncryptError {}

#[allow(clippy::module_name_repetitions)]
pub type EncryptResult<T> = Result<T, EncryptError>;

pub trait Encrypt {
    fn name(&self) -> &'static str;
    fn block_size(&self) -> usize;
    fn encrypt(&mut self, pkt: &Bytes) -> EncryptResult<Bytes>;
}

use bytes::Bytes;

pub use aes::*;
pub use plain::*;

mod aes;
mod plain;

#[derive(Debug)]
pub enum EncryptError {}

pub type EncryptResult<T> = Result<T, EncryptError>;

pub trait Encrypt {
    fn name(&self) -> &'static str;
    fn block_size(&self) -> usize;
    fn encrypt(&mut self, pkt: &Bytes) -> EncryptResult<Bytes>;
}

use bytes::Bytes;

pub use none::*;
pub use sha::*;

mod none;
mod sha;

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum MacError {}

#[allow(clippy::module_name_repetitions)]
pub type MacResult<T> = Result<T, MacError>;

pub trait Mac {
    fn size(&self) -> usize;
    fn name(&self) -> &'static str;
    fn sign(&self, seq: u32, plain: &Bytes, encrypted: &Bytes) -> MacResult<Bytes>;
}

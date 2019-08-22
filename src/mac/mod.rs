use bytes::Bytes;

pub use none::*;
pub use sha::*;

mod none;
mod sha;

pub trait Mac {
    fn size(&self) -> usize;
    fn name(&self) -> &'static str;
    fn sign(&self, seq: u32, plain: &Bytes, encrypted: &Bytes) -> Bytes;
}

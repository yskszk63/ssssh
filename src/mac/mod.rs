use bytes::Bytes;

pub(crate) use none::*;
pub(crate) use sha::*;

mod none;
mod sha;

pub(crate) trait Mac {
    fn size(&self) -> usize;
    fn name(&self) -> &'static str;
    fn sign(&self, seq: u32, plain: &Bytes, encrypted: &Bytes) -> Bytes;
}

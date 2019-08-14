use bytes::Bytes;

pub use none::*;

mod none;

#[derive(Debug)]
pub enum CompressionError {}

pub type CompressionResult<T> = Result<T, CompressionError>;

pub trait Compression {
    fn compress(&self, target: &Bytes) -> CompressionResult<Bytes>;
    fn decompress(&self, target: &Bytes) -> CompressionResult<Bytes>;
}

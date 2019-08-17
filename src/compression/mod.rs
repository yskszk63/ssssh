use bytes::Bytes;

pub use none::*;

mod none;

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum CompressionError {}

#[allow(clippy::module_name_repetitions)]
pub type CompressionResult<T> = Result<T, CompressionError>;

pub trait Compression {
    fn compress(&self, target: &Bytes) -> CompressionResult<Bytes>;
    fn decompress(&self, target: &Bytes) -> CompressionResult<Bytes>;
}

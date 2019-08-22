use bytes::Bytes;

use failure::Fail;

pub use none::*;

mod none;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Fail)]
#[fail(display = "")] // TODO
pub struct CompressionError {}

#[allow(clippy::module_name_repetitions)]
pub type CompressionResult<T> = Result<T, CompressionError>;

pub trait Compression {
    fn compress(&self, target: &Bytes) -> CompressionResult<Bytes>;
    fn decompress(&self, target: &Bytes) -> CompressionResult<Bytes>;
}

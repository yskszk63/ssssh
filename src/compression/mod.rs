use bytes::Bytes;

use failure::Fail;

pub(crate) use none::*;

mod none;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Fail)]
#[fail(display = "")] // TODO
pub(crate) struct CompressionError {}

#[allow(clippy::module_name_repetitions)]
pub(crate) type CompressionResult<T> = Result<T, CompressionError>;

pub(crate) trait Compression {
    fn compress(&self, target: &Bytes) -> CompressionResult<Bytes>;
    fn decompress(&self, target: &Bytes) -> CompressionResult<Bytes>;
}

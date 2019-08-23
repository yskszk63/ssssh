use bytes::Bytes;

use super::{Compression, CompressionResult};

#[allow(clippy::module_name_repetitions)]
pub(crate) struct NoneCompression;

impl Compression for NoneCompression {
    fn compress(&self, target: &Bytes) -> CompressionResult<Bytes> {
        Ok(target.clone())
    }
    fn decompress(&self, target: &Bytes) -> CompressionResult<Bytes> {
        Ok(target.clone())
    }
}

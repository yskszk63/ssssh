use bytes::Bytes;

use super::{Compression, CompressionResult};

pub struct NoneCompression;

impl Compression for NoneCompression {
    fn compress(&self, target: &Bytes) -> CompressionResult<Bytes> {
        Ok(target.clone())
    }
    fn decompress(&self, target: &Bytes) -> CompressionResult<Bytes> {
        Ok(target.clone())
    }
}

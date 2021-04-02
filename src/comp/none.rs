//! `none` compression algorithm
use bytes::Buf as _;

use super::*;

/// `none` compression algorithm
#[derive(Debug)]
pub(crate) struct None {}

impl CompressionTrait for None {
    const NAME: Algorithm = Algorithm::None;

    fn new() -> Self {
        Self {}
    }

    fn compress(&self, mut target: &[u8]) -> Result<Bytes, SshError> {
        Ok(target.copy_to_bytes(target.remaining()))
    }

    fn decompress(&self, mut target: &[u8]) -> Result<Bytes, SshError> {
        Ok(target.copy_to_bytes(target.remaining()))
    }
}

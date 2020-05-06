//! Compression
//!
//! [rfc4253](https://tools.ietf.org/html/rfc4253#section-6.2)

use bytes::Bytes;
use thiserror::Error;

mod none;

/// Compression errors
#[derive(Debug, Error)]
pub enum CompressionError {
    /// Unknown compression algorithm
    #[error("unknown compression {0:}")]
    UnknownCompression(String),
}

/// Compression algorithm trait
trait CompressionTrait: Sized {
    /// algorithm name
    const NAME: &'static str;

    /// Create new instance
    fn new() -> Self;

    /// Compress target into bytes
    fn compress(&self, target: &[u8]) -> Result<Bytes, CompressionError>;

    /// Decompress target into bytes
    fn decompress(&self, target: &[u8]) -> Result<Bytes, CompressionError>;
}

/// Compression algorithms
#[derive(Debug)]
pub(crate) enum Compression {
    None(none::None),
}

impl Compression {
    /// Supported compression algorithms
    pub(crate) fn defaults() -> Vec<String> {
        vec![none::None::NAME.to_string()]
    }

    /// Create new instance by algorithm name
    pub(crate) fn new(name: &str) -> Result<Self, CompressionError> {
        match name {
            none::None::NAME => Ok(Self::None(none::None::new())),
            x => Err(CompressionError::UnknownCompression(x.to_string())),
        }
    }

    /// Compress target into bytes
    pub(crate) fn compress(&self, target: &[u8]) -> Result<Bytes, CompressionError> {
        match self {
            Self::None(item) => item.compress(target),
        }
    }

    /// Decompress target into bytes
    pub(crate) fn decompress(&self, target: &[u8]) -> Result<Bytes, CompressionError> {
        match self {
            Self::None(item) => item.decompress(target),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<Compression>();
        assert::<CompressionError>();
    }
}

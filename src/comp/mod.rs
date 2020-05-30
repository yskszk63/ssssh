//! Compression
//!
//! [rfc4253](https://tools.ietf.org/html/rfc4253#section-6.2)

use bytes::Bytes;

use crate::SshError;

mod none;

/// Compression algorithm trait
trait CompressionTrait: Sized {
    /// algorithm name
    const NAME: &'static str;

    /// Create new instance
    fn new() -> Self;

    /// Compress target into bytes
    fn compress(&self, target: &[u8]) -> Result<Bytes, SshError>;

    /// Decompress target into bytes
    fn decompress(&self, target: &[u8]) -> Result<Bytes, SshError>;
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
    pub(crate) fn new(name: &str) -> Result<Self, SshError> {
        match name {
            none::None::NAME => Ok(Self::None(none::None::new())),
            x => Err(SshError::UnknownAlgorithm(x.to_string())),
        }
    }

    /// Compress target into bytes
    pub(crate) fn compress(&self, target: &[u8]) -> Result<Bytes, SshError> {
        match self {
            Self::None(item) => item.compress(target),
        }
    }

    /// Decompress target into bytes
    pub(crate) fn decompress(&self, target: &[u8]) -> Result<Bytes, SshError> {
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
    }
}

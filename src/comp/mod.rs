//! Compression
//!
//! [rfc4253](https://tools.ietf.org/html/rfc4253#section-6.2)

use std::str::FromStr;

use bytes::Bytes;

use crate::negotiate::{AlgorithmName, UnknownNameError};
use crate::SshError;

mod none;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Algorithm {
    None,
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        match self {
            Self::None => "none",
        }
    }
}

impl FromStr for Algorithm {
    type Err = UnknownNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            x => Err(UnknownNameError(x.into())),
        }
    }
}

impl AlgorithmName for Algorithm {
    fn defaults() -> Vec<Self> {
        vec![Self::None]
    }
}

/// Compression algorithm trait
trait CompressionTrait: Sized {
    /// algorithm name
    const NAME: Algorithm;

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
    pub(crate) fn new_none() -> Self {
        Self::new(&Algorithm::None)
    }

    /// Create new instance by algorithm name
    pub(crate) fn new(name: &Algorithm) -> Self {
        match name {
            Algorithm::None => Self::None(none::None::new()),
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

    #[test]
    fn test_parse() {
        for name in Algorithm::defaults() {
            let s = name.as_ref();
            let a = Algorithm::from_str(s).unwrap();
            assert_eq!(name, a);
        }

        Algorithm::from_str("").unwrap_err();
    }
}

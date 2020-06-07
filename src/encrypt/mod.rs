//! Encrypt
//!
//! [rfc4253](https://tools.ietf.org/html/rfc4253)

use std::str::FromStr;

use bytes::{Bytes, BytesMut};

use crate::negotiate::{AlgorithmName, UnknownNameError};
use crate::SshError;

mod aes;
mod none;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Algorithm {
    None,
    Aes256Ctr,
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        match self {
            Self::None => "non",
            Self::Aes256Ctr => "aes256-ctr",
        }
    }
}

impl FromStr for Algorithm {
    type Err = UnknownNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "aes256-ctr" => Ok(Self::Aes256Ctr),
            x => Err(UnknownNameError(x.into())),
        }
    }
}

impl AlgorithmName for Algorithm {
    fn defaults() -> Vec<Self> {
        vec![Self::Aes256Ctr]
    }
}

/// Encrypt algorithm trait
trait EncryptTrait: Into<Encrypt> + Sized {
    /// Encrypt algorithm name
    const NAME: Algorithm;

    /// Encrypt block size
    const BLOCK_SIZE: usize;

    /// Encrypt key length
    const KEY_LENGTH: usize;

    /// Create new instance for encrypt
    fn new_for_encrypt(key: &[u8], iv: &[u8]) -> Result<Self, SshError>;

    /// Create new instance for dncrypt
    fn new_for_decrypt(key: &[u8], iv: &[u8]) -> Result<Self, SshError>;

    /// Update encrypt or decrypt block
    fn update(&mut self, src: &[u8], dst: &mut BytesMut) -> Result<(), SshError>;
}

/// Encrypt algorithms
#[derive(Debug)]
pub(crate) enum Encrypt {
    /// `none` algorithm
    None(none::None),

    /// `aes256-ctr` algorithm
    Aes256Ctr(aes::Aes256Ctr),
}

impl Encrypt {
    /// Create `none` instance
    pub(crate) fn new_none() -> Self {
        Encrypt::None(none::None::new())
    }

    /// Create new instance for encrypt by name
    pub(crate) fn new_for_encrypt(
        name: &Algorithm,
        key: &Bytes,
        iv: &Bytes,
    ) -> Result<Self, SshError> {
        match name {
            Algorithm::None => Ok(none::None::new_for_encrypt(key, iv)?.into()),
            Algorithm::Aes256Ctr => Ok(aes::Aes256Ctr::new_for_encrypt(key, iv)?.into()),
        }
    }

    /// Create new instance for decrypt by name
    pub(crate) fn new_for_decrypt(
        name: &Algorithm,
        key: &Bytes,
        iv: &Bytes,
    ) -> Result<Self, SshError> {
        match name {
            Algorithm::None => Ok(none::None::new_for_decrypt(key, iv)?.into()),
            Algorithm::Aes256Ctr => Ok(aes::Aes256Ctr::new_for_decrypt(key, iv)?.into()),
        }
    }

    /// Get block size by name
    pub(crate) fn block_size_by_name(name: &Algorithm) -> usize {
        match name {
            Algorithm::None => none::None::BLOCK_SIZE,
            Algorithm::Aes256Ctr => aes::Aes256Ctr::BLOCK_SIZE,
        }
    }

    /// Get key length by name
    pub(crate) fn key_length_by_name(name: &Algorithm) -> usize {
        match name {
            Algorithm::None => none::None::KEY_LENGTH,
            Algorithm::Aes256Ctr => aes::Aes256Ctr::KEY_LENGTH,
        }
    }

    /// Get block size
    pub(crate) fn block_size(&self) -> usize {
        match self {
            Self::None(..) => none::None::BLOCK_SIZE,
            Self::Aes256Ctr(..) => aes::Aes256Ctr::BLOCK_SIZE,
        }
    }

    /// Update encrypt or decrypt block
    pub(crate) fn update(&mut self, src: &[u8], dst: &mut BytesMut) -> Result<(), SshError> {
        match self {
            Self::None(item) => item.update(src, dst),
            Self::Aes256Ctr(item) => item.update(src, dst),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<Encrypt>();
    }

    #[test]
    fn test_none() {
        let name = &Algorithm::None;

        let k = Bytes::from(vec![0; Encrypt::key_length_by_name(name)]);
        let iv = Bytes::from(vec![0; Encrypt::block_size_by_name(name)]);

        let src = BytesMut::from("Hello, world!");
        let mut dst = BytesMut::new();
        let mut result = BytesMut::new();

        Encrypt::new_for_encrypt(name, &k, &iv)
            .unwrap()
            .update(&src, &mut dst)
            .unwrap();
        Encrypt::new_for_decrypt(name, &k, &iv)
            .unwrap()
            .update(&dst, &mut result)
            .unwrap();

        assert_eq!(&src, &result);

        Encrypt::new_none();
    }

    #[test]
    fn test_aes256ctr() {
        let name = &Algorithm::Aes256Ctr;

        let k = Bytes::from(vec![0; Encrypt::key_length_by_name(name)]);
        let iv = Bytes::from(vec![0; Encrypt::block_size_by_name(name)]);

        let src = BytesMut::from("Hello, world!");
        let mut dst = BytesMut::new();
        let mut result = BytesMut::new();

        Encrypt::new_for_encrypt(name, &k, &iv)
            .unwrap()
            .update(&src, &mut dst)
            .unwrap();
        Encrypt::new_for_decrypt(name, &k, &iv)
            .unwrap()
            .update(&dst, &mut result)
            .unwrap();

        assert_eq!(&src, &result);
    }
}

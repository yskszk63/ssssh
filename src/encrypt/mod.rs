//! Encrypt
//!
//! [rfc4253](https://tools.ietf.org/html/rfc4253)

use bytes::{Bytes, BytesMut};

use crate::SshError;

mod aes;
mod none;

/// Encrypt algorithm trait
trait EncryptTrait: Into<Encrypt> + Sized {
    /// Encrypt algorithm name
    const NAME: &'static str;

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
    /// Supported encrypt algorithms
    pub(crate) fn defaults() -> Vec<String> {
        vec![aes::Aes256Ctr::NAME.to_string()]
    }

    /// Create `none` instance
    pub(crate) fn new_none() -> Self {
        Encrypt::None(none::None::new())
    }

    /// Create new instance for encrypt by name
    pub(crate) fn new_for_encrypt(name: &str, key: &Bytes, iv: &Bytes) -> Result<Self, SshError> {
        Ok(match name {
            none::None::NAME => none::None::new_for_encrypt(key, iv)?.into(),
            aes::Aes256Ctr::NAME => aes::Aes256Ctr::new_for_encrypt(key, iv)?.into(),
            v => return Err(SshError::UnknownAlgorithm(v.to_string())),
        })
    }

    /// Create new instance for decrypt by name
    pub(crate) fn new_for_decrypt(name: &str, key: &Bytes, iv: &Bytes) -> Result<Self, SshError> {
        Ok(match name {
            none::None::NAME => none::None::new_for_decrypt(key, iv)?.into(),
            aes::Aes256Ctr::NAME => aes::Aes256Ctr::new_for_decrypt(key, iv)?.into(),
            v => return Err(SshError::UnknownAlgorithm(v.to_string())),
        })
    }

    /// Get block size by name
    pub(crate) fn block_size_by_name(name: &str) -> Result<usize, SshError> {
        Ok(match name {
            none::None::NAME => none::None::BLOCK_SIZE,
            aes::Aes256Ctr::NAME => aes::Aes256Ctr::BLOCK_SIZE,
            x => return Err(SshError::UnknownAlgorithm(x.into())),
        })
    }

    /// Get key length by name
    pub(crate) fn key_length_by_name(name: &str) -> Result<usize, SshError> {
        Ok(match name {
            none::None::NAME => none::None::KEY_LENGTH,
            aes::Aes256Ctr::NAME => aes::Aes256Ctr::KEY_LENGTH,
            x => return Err(SshError::UnknownAlgorithm(x.into())),
        })
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
    fn test_unknown() {
        let k = Bytes::from("");
        let iv = Bytes::from("");
        Encrypt::new_for_encrypt("-", &k, &iv).unwrap_err();
        Encrypt::new_for_decrypt("-", &k, &iv).unwrap_err();
    }

    #[test]
    fn test_none() {
        let name = "none";

        let k = Bytes::from(vec![0; Encrypt::key_length_by_name(name).unwrap()]);
        let iv = Bytes::from(vec![0; Encrypt::block_size_by_name(name).unwrap()]);

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
        let name = "aes256-ctr";

        let k = Bytes::from(vec![0; Encrypt::key_length_by_name(name).unwrap()]);
        let iv = Bytes::from(vec![0; Encrypt::block_size_by_name(name).unwrap()]);

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

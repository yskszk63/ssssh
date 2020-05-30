//! `aes256-ctr` encrypt algorithm
use std::fmt;

use bytes::BytesMut;
use openssl::symm::{Cipher, Crypter, Mode};

use super::*;

/// `aes256-ctr` encrypt algorithm
pub(crate) struct Aes256Ctr {
    crypter: Crypter,
}

impl fmt::Debug for Aes256Ctr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aes256Ctr")
    }
}

impl EncryptTrait for Aes256Ctr {
    const NAME: &'static str = "aes256-ctr";
    const BLOCK_SIZE: usize = 16;
    const KEY_LENGTH: usize = 32;

    fn new_for_encrypt(key: &[u8], iv: &[u8]) -> Result<Self, SshError> {
        let crypter = Crypter::new(Cipher::aes_256_ctr(), Mode::Encrypt, key, Some(&iv))
            .map_err(SshError::encrypt_error)?;
        Ok(Self { crypter })
    }

    fn new_for_decrypt(key: &[u8], iv: &[u8]) -> Result<Self, SshError> {
        let crypter = Crypter::new(Cipher::aes_256_ctr(), Mode::Decrypt, key, Some(&iv))
            .map_err(SshError::encrypt_error)?;
        Ok(Self { crypter })
    }

    fn update(&mut self, src: &[u8], dst: &mut BytesMut) -> Result<(), SshError> {
        let mut tail = dst.split_off(dst.len());
        tail.extend_from_slice(&vec![0; src.len()]);
        self.crypter
            .update(src, &mut tail)
            .map_err(SshError::encrypt_error)?;
        dst.unsplit(tail);
        Ok(())
    }
}

impl From<Aes256Ctr> for Encrypt {
    fn from(v: Aes256Ctr) -> Self {
        Self::Aes256Ctr(v)
    }
}

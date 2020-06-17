//! `aes256-ctr` encrypt algorithm
use std::fmt;

use openssl::symm::{Cipher, Crypter, Mode};

use super::*;

/// `aes256-ctr` encrypt algorithm
pub(crate) struct Aes256Ctr {
    crypter: Crypter,
}

impl Aes256Ctr {
    fn new(key: &[u8], iv: &[u8], mode: Mode) -> Result<Self, SshError> {
        let crypter = Crypter::new(Cipher::aes_256_ctr(), mode, key, Some(&iv))
            .map_err(SshError::encrypt_error)?;
        Ok(Self { crypter })
    }
}

impl fmt::Debug for Aes256Ctr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aes256Ctr")
    }
}

impl EncryptTrait for Aes256Ctr {
    const NAME: Algorithm = Algorithm::Aes256Ctr;
    const BLOCK_SIZE: usize = 16;
    const KEY_LENGTH: usize = 32;

    fn new_for_encrypt(key: &[u8], iv: &[u8]) -> Result<Self, SshError> {
        Self::new(key, iv, Mode::Encrypt)
    }

    fn new_for_decrypt(key: &[u8], iv: &[u8]) -> Result<Self, SshError> {
        Self::new(key, iv, Mode::Decrypt)
    }

    fn update(&mut self, target: &mut [u8]) -> Result<(), SshError> {
        let mut buf = [0; Self::BLOCK_SIZE * 64];

        for chunk in target.chunks_mut(buf.len()) {
            let b = &mut buf[..chunk.len()];
            b.clone_from_slice(chunk);
            self.crypter
                .update(&b, chunk)
                .map_err(SshError::encrypt_error)?;
        }
        Ok(())
    }
}

impl From<Aes256Ctr> for Encrypt {
    fn from(v: Aes256Ctr) -> Self {
        Self::Aes256Ctr(v)
    }
}

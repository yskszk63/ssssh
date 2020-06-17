//! `aes` cipher algorithm
use std::fmt;
use std::marker::PhantomData;

use openssl::symm::{Cipher, Crypter, Mode};

use super::*;

pub(crate) type Aes256Ctr = Aes<Aes256CtrCipher>;
pub(crate) type Aes192Ctr = Aes<Aes192CtrCipher>;
pub(crate) type Aes128Ctr = Aes<Aes128CtrCipher>;

pub(crate) trait AesCipherTrait {
    const KEY_LENGTH: usize;
    fn openssl_cipher() -> Cipher;
}

#[derive(Debug)]
pub(crate) enum Aes256CtrCipher {}

impl AesCipherTrait for Aes256CtrCipher {
    const KEY_LENGTH: usize = 32;
    fn openssl_cipher() -> Cipher {
        Cipher::aes_256_ctr()
    }
}

#[derive(Debug)]
pub(crate) enum Aes192CtrCipher {}

impl AesCipherTrait for Aes192CtrCipher {
    const KEY_LENGTH: usize = 24;
    fn openssl_cipher() -> Cipher {
        Cipher::aes_192_ctr()
    }
}

#[derive(Debug)]
pub(crate) enum Aes128CtrCipher {}

impl AesCipherTrait for Aes128CtrCipher {
    const KEY_LENGTH: usize = 16;
    fn openssl_cipher() -> Cipher {
        Cipher::aes_128_ctr()
    }
}

/// `aes` cipher algorithm
pub(crate) struct Aes<T> {
    crypter: Crypter,
    _phantom: PhantomData<T>,
}

impl<T> Aes<T>
where
    T: AesCipherTrait,
{
    fn new(key: &[u8], iv: &[u8], mode: Mode) -> Result<Self, SshError> {
        let crypter = Crypter::new(T::openssl_cipher(), mode, key, Some(&iv))
            .map_err(SshError::cipher_error)?;
        Ok(Self {
            crypter,
            _phantom: PhantomData,
        })
    }
}

impl<T> fmt::Debug for Aes<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Aes")
    }
}

impl<T> CipherTrait for Aes<T>
where
    T: AesCipherTrait,
{
    const BLOCK_SIZE: usize = 16;
    const KEY_LENGTH: usize = T::KEY_LENGTH;

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
                .map_err(SshError::cipher_error)?;
        }
        Ok(())
    }
}

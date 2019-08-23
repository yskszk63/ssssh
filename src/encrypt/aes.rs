use bytes::{BufMut, Bytes, BytesMut};
use openssl::symm::{Cipher, Crypter, Mode};

use super::{Encrypt, EncryptResult};

#[allow(clippy::module_name_repetitions)]
pub(crate) struct Aes256CtrEncrypt {
    encrypter: openssl::symm::Crypter,
}

impl Aes256CtrEncrypt {
    pub(crate) fn new_for_encrypt(key: &Bytes, iv: &Bytes) -> EncryptResult<Self> {
        Self::new(key, iv, Mode::Encrypt)
    }

    pub(crate) fn new_for_decrypt(key: &Bytes, iv: &Bytes) -> EncryptResult<Self> {
        Self::new(key, iv, Mode::Decrypt)
    }

    fn new(key: &Bytes, iv: &Bytes, mode: Mode) -> EncryptResult<Self> {
        let encrypter = Crypter::new(Cipher::aes_256_ctr(), mode, &key, Some(&iv))?;
        Ok(Self { encrypter })
    }
}

impl Encrypt for Aes256CtrEncrypt {
    fn name(&self) -> &'static str {
        "aes_256_ctr"
    }
    fn block_size(&self) -> usize {
        //openssl::symm::Cipher::aes_256_ctr().block_size()
        16
    }
    fn encrypt(&mut self, pkt: &Bytes) -> EncryptResult<Bytes> {
        let bs = self.block_size();

        let mut pkt = pkt.clone();
        let mut r = BytesMut::with_capacity(pkt.len());
        let mut b = vec![0; bs];

        while !pkt.is_empty() {
            let c = self.encrypter.update(&pkt.split_to(bs), &mut b)?;
            r.put_slice(&b[..c]);
        }
        Ok(r.freeze())
    }
}

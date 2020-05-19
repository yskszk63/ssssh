use std::num::Wrapping;

use bytes::{BufMut as _, Bytes, BytesMut};
use getset::{Getters, MutGetters};
use thiserror::Error;

use crate::comp::{Compression, CompressionError};
use crate::encrypt::{Encrypt, EncryptError};
use crate::kex::Kex;
use crate::mac::{Mac, MacError};
use crate::negotiate::Algorithm;
use crate::pack::{Mpint, Pack};

#[derive(Debug, Error)]
pub enum ChangeKeyError {
    #[error(transparent)]
    EncryptError(#[from] EncryptError),

    #[error(transparent)]
    MacError(#[from] MacError),

    #[error(transparent)]
    CompressionError(#[from] CompressionError),
}

#[derive(Debug, Getters, MutGetters)]
pub(crate) struct OneWayState {
    seq: Wrapping<u32>,

    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    encrypt: Encrypt,

    #[get = "pub(crate)"]
    mac: Mac,

    #[get = "pub(crate)"]
    comp: Compression,
}

impl OneWayState {
    fn new() -> Self {
        Self {
            seq: Wrapping(0),
            encrypt: Encrypt::new_none(),
            mac: Mac::new_none(),
            comp: Compression::new("none").unwrap(),
        }
    }

    pub(crate) fn get_and_inc_seq(&mut self) -> u32 {
        let r = self.seq;
        self.seq += Wrapping(1);
        r.0
    }
}

fn compute_hash(
    hash: &Bytes,
    key: &Bytes,
    kind: u8,
    session_id: &Bytes,
    kex: &Kex,
    len: usize,
) -> Bytes {
    let mut result = BytesMut::new();

    let mut buf = BytesMut::new();
    Mpint::new(key.clone()).pack(&mut buf);
    buf.put_slice(hash);
    buf.put_u8(kind);
    buf.put_slice(session_id);
    result.put_slice(&kex.hash(&buf));

    while result.len() < len {
        let last = result.clone().freeze();
        let mut buf = BytesMut::new();
        Mpint::new(key.clone()).pack(&mut buf);
        buf.put_slice(hash);
        buf.put_slice(&last);
        result.put_slice(&kex.hash(&buf));
    }

    result.freeze().split_to(len)
}

#[derive(Debug, Getters, MutGetters)]
pub(crate) struct State {
    session_id: Option<Bytes>,

    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    ctos: OneWayState,

    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    stoc: OneWayState,
}

impl State {
    pub(crate) fn new() -> Self {
        Self {
            session_id: None,
            ctos: OneWayState::new(),
            stoc: OneWayState::new(),
        }
    }

    pub(crate) fn change_key(
        &mut self,
        hash: &Bytes,
        secret: &Bytes,
        kex: &Kex,
        algorithm: &Algorithm,
    ) -> Result<(), ChangeKeyError> {
        let session_id = self.session_id.as_ref().unwrap_or_else(|| &hash);

        let iv_ctos_len = Encrypt::block_size_by_name(algorithm.encryption_algorithm_c2s())?;
        let iv_ctos = compute_hash(hash, secret, b'A', session_id, kex, iv_ctos_len);
        let iv_stoc_len = Encrypt::block_size_by_name(algorithm.encryption_algorithm_c2s())?;
        let iv_stoc = compute_hash(hash, secret, b'B', session_id, kex, iv_stoc_len);

        let key_ctos_len = Encrypt::key_length_by_name(algorithm.encryption_algorithm_c2s())?;
        let key_ctos = compute_hash(hash, secret, b'C', session_id, kex, key_ctos_len);
        let key_stoc_len = Encrypt::key_length_by_name(algorithm.encryption_algorithm_c2s())?;
        let key_stoc = compute_hash(hash, secret, b'D', session_id, kex, key_stoc_len);

        let intk_ctos_len = Mac::len_by_name(algorithm.mac_algorithm_c2s())?;
        let intk_ctos = compute_hash(hash, secret, b'E', session_id, kex, intk_ctos_len);
        let intk_stoc_len = Mac::len_by_name(algorithm.mac_algorithm_c2s())?;
        let intk_stoc = compute_hash(hash, secret, b'F', session_id, kex, intk_stoc_len);

        self.ctos.encrypt =
            Encrypt::new_for_decrypt(algorithm.encryption_algorithm_c2s(), &key_ctos, &iv_ctos)?;
        self.stoc.encrypt =
            Encrypt::new_for_encrypt(algorithm.encryption_algorithm_s2c(), &key_stoc, &iv_stoc)?;

        self.ctos.mac = Mac::new(algorithm.mac_algorithm_c2s(), &intk_ctos)?;
        self.stoc.mac = Mac::new(algorithm.mac_algorithm_s2c(), &intk_stoc)?;

        self.ctos.comp = Compression::new(algorithm.compression_algorithm_c2s())?;
        self.stoc.comp = Compression::new(algorithm.compression_algorithm_s2c())?;

        self.session_id = Some(session_id.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<State>();
        assert::<ChangeKeyError>();
    }
}

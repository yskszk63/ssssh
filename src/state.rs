use std::num::Wrapping;

use bytes::{Bytes, BytesMut};
use getset::{Getters, MutGetters};

use crate::cipher::Cipher;
use crate::comp::Compression;
use crate::kex::Kex;
use crate::mac::Mac;
use crate::negotiate::Algorithm;
use crate::pack::{Mpint, Pack, Put};
use crate::SshError;

#[derive(Debug, Getters, MutGetters)]
pub(crate) struct OneWayState {
    seq: Wrapping<u32>,

    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    cipher: Cipher,

    #[get = "pub(crate)"]
    mac: Mac,

    #[get = "pub(crate)"]
    comp: Compression,
}

impl OneWayState {
    fn new() -> Self {
        Self {
            seq: Wrapping(0),
            cipher: Cipher::new_none(),
            mac: Mac::new_none(),
            comp: Compression::new_none(),
        }
    }

    pub(crate) fn get_and_inc_seq(&mut self) -> u32 {
        let r = self.seq;
        self.seq += Wrapping(1);
        r.0
    }

    pub(crate) fn seq(&self) -> u32 {
        self.seq.0
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

    let mut hasher = kex.hasher();
    Mpint::new(key.clone()).pack(&mut hasher);
    hasher.put(hash);
    kind.pack(&mut hasher);
    hasher.put(session_id);
    result.extend_from_slice(&hasher.finish());

    while result.len() < len {
        let last = result.clone().freeze();
        let mut hasher = kex.hasher();
        Mpint::new(key.clone()).pack(&mut hasher);
        hasher.put(hash);
        hasher.put(&last);
        result.extend_from_slice(&hasher.finish());
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

    pub(crate) fn session_id(&self) -> &[u8] {
        self.session_id.as_ref().unwrap()
    }

    pub(crate) fn change_key(
        &mut self,
        hash: &Bytes,
        secret: &Bytes,
        kex: &Kex,
        algorithm: &Algorithm,
    ) -> Result<(), SshError> {
        let session_id = self.session_id.as_ref().unwrap_or(&hash);

        let iv_ctos_len = Cipher::block_size_by_name(algorithm.cipher_algorithm_c2s());
        let iv_ctos = compute_hash(hash, secret, b'A', session_id, kex, iv_ctos_len);
        let iv_stoc_len = Cipher::block_size_by_name(algorithm.cipher_algorithm_c2s());
        let iv_stoc = compute_hash(hash, secret, b'B', session_id, kex, iv_stoc_len);

        let key_ctos_len = Cipher::key_length_by_name(algorithm.cipher_algorithm_c2s());
        let key_ctos = compute_hash(hash, secret, b'C', session_id, kex, key_ctos_len);
        let key_stoc_len = Cipher::key_length_by_name(algorithm.cipher_algorithm_c2s());
        let key_stoc = compute_hash(hash, secret, b'D', session_id, kex, key_stoc_len);

        let intk_ctos_len = Mac::len_by_name(algorithm.mac_algorithm_c2s());
        let intk_ctos = compute_hash(hash, secret, b'E', session_id, kex, intk_ctos_len);
        let intk_stoc_len = Mac::len_by_name(algorithm.mac_algorithm_c2s());
        let intk_stoc = compute_hash(hash, secret, b'F', session_id, kex, intk_stoc_len);

        self.ctos.cipher =
            Cipher::new_for_decrypt(algorithm.cipher_algorithm_c2s(), &key_ctos, &iv_ctos)?;
        self.stoc.cipher =
            Cipher::new_for_encrypt(algorithm.cipher_algorithm_s2c(), &key_stoc, &iv_stoc)?;

        self.ctos.mac = Mac::new(algorithm.mac_algorithm_c2s(), &intk_ctos);
        self.stoc.mac = Mac::new(algorithm.mac_algorithm_s2c(), &intk_stoc);

        self.ctos.comp = Compression::new(algorithm.compression_algorithm_c2s());
        self.stoc.comp = Compression::new(algorithm.compression_algorithm_s2c());

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
    }
}

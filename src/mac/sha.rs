use std::marker::PhantomData;

use bytes::{Buf, BytesMut};

use super::*;
use ring::hmac::{
    self, Algorithm as RingAlgorithm, Context, Key, HMAC_SHA1_FOR_LEGACY_USE_ONLY as HMAC_SHA1,
    HMAC_SHA256, HMAC_SHA512,
};

pub(crate) type HmacSha256 = HmacSha<HmacSha256Meta>;
pub(crate) type HmacSha512 = HmacSha<HmacSha512Meta>;
pub(crate) type HmacSha1 = HmacSha<HmacSha1Meta>;

pub(crate) trait HmacShaTrait {
    const LEN: usize;
    fn algorithm() -> RingAlgorithm;
}

#[derive(Debug)]
pub(crate) enum HmacSha256Meta {}

impl HmacShaTrait for HmacSha256Meta {
    const LEN: usize = 32;
    fn algorithm() -> RingAlgorithm {
        HMAC_SHA256
    }
}

#[derive(Debug)]
pub(crate) enum HmacSha512Meta {}

impl HmacShaTrait for HmacSha512Meta {
    const LEN: usize = 64;
    fn algorithm() -> RingAlgorithm {
        HMAC_SHA512
    }
}

#[derive(Debug)]
pub(crate) enum HmacSha1Meta {}

impl HmacShaTrait for HmacSha1Meta {
    const LEN: usize = 20;
    fn algorithm() -> RingAlgorithm {
        HMAC_SHA1
    }
}

#[derive(Debug)]
pub(crate) struct HmacSha<T> {
    key: Key,
    _phantom: PhantomData<T>,
}

impl<T> MacTrait for HmacSha<T>
where
    T: HmacShaTrait,
{
    const LEN: usize = T::LEN;

    fn new(key: &[u8]) -> Self {
        let key = Key::new(T::algorithm(), &key);
        Self {
            key,
            _phantom: PhantomData,
        }
    }

    fn sign(&self, seq: u32, plain: &[u8]) -> Result<Bytes, SshError> {
        let mut cx = Context::with_key(&self.key);
        cx.update(&seq.to_be_bytes());
        cx.update(&plain);
        Ok(cx.sign().as_ref().to_bytes())
    }

    fn verify(&self, seq: u32, plain: &[u8], tag: &[u8]) -> Result<(), SshError> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&plain);
        hmac::verify(&self.key, &buf, tag).map_err(SshError::mac_error)?;
        Ok(())
    }
}

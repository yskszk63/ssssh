use bytes::{Buf, BytesMut};

use super::*;
use ring::hmac::{self, Context, Key, HMAC_SHA1_FOR_LEGACY_USE_ONLY as HMAC_SHA1, HMAC_SHA256};

#[derive(Debug)]
pub(crate) struct HmacSha256 {
    key: Key,
}

impl MacTrait for HmacSha256 {
    const NAME: Algorithm = Algorithm::HmacSha256;
    const LEN: usize = 32;

    fn new(key: &[u8]) -> Self {
        let key = Key::new(HMAC_SHA256, &key);
        Self { key }
    }

    fn sign(&self, seq: u32, plain: &[u8], _encrypted: &[u8]) -> Result<Bytes, SshError> {
        let mut cx = Context::with_key(&self.key);
        cx.update(&seq.to_be_bytes());
        cx.update(&plain);
        Ok(cx.sign().as_ref().to_bytes())
    }

    fn verify(
        &self,
        seq: u32,
        plain: &[u8],
        _encrypted: &[u8],
        tag: &[u8],
    ) -> Result<(), SshError> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&plain);
        hmac::verify(&self.key, &buf, tag).map_err(SshError::mac_error)?;
        Ok(())
    }
}

impl From<HmacSha256> for Mac {
    fn from(v: HmacSha256) -> Self {
        Self::HmacSha256(v)
    }
}

#[derive(Debug)]
pub(crate) struct HmacSha1 {
    key: Key,
}

impl MacTrait for HmacSha1 {
    const NAME: Algorithm = Algorithm::HmacSha1;
    const LEN: usize = 20;

    fn new(key: &[u8]) -> Self {
        let key = Key::new(HMAC_SHA1, &key);
        Self { key }
    }

    fn sign(&self, seq: u32, plain: &[u8], _encrypted: &[u8]) -> Result<Bytes, SshError> {
        let mut cx = Context::with_key(&self.key);
        cx.update(&seq.to_be_bytes());
        cx.update(&plain);
        Ok(cx.sign().as_ref().to_bytes())
    }

    fn verify(
        &self,
        seq: u32,
        plain: &[u8],
        _encrypted: &[u8],
        tag: &[u8],
    ) -> Result<(), SshError> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&seq.to_be_bytes());
        buf.extend_from_slice(&plain);
        hmac::verify(&self.key, &buf, tag).map_err(SshError::mac_error)?;
        Ok(())
    }
}

impl From<HmacSha1> for Mac {
    fn from(v: HmacSha1) -> Self {
        Self::HmacSha1(v)
    }
}

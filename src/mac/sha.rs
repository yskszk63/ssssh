use bytes::Bytes;
use ring::hmac::{Context, Key, HMAC_SHA1_FOR_LEGACY_USE_ONLY as HMAC_SHA1, HMAC_SHA256};

use super::MacType;

pub(crate) struct HmacSha2_256 {
    key: Key,
}

impl HmacSha2_256 {
    pub fn new(key: &Bytes) -> Self {
        let key = Key::new(HMAC_SHA256, &key);
        Self { key }
    }
}

impl MacType for HmacSha2_256 {
    fn size(&self) -> usize {
        32
    }
    fn name(&self) -> &'static str {
        "hmac-sha2-256"
    }
    fn sign(&self, seq: u32, plain: &Bytes, _encrypted: &Bytes) -> Bytes {
        let mut ctx = Context::with_key(&self.key);
        ctx.update(&seq.to_be_bytes());
        ctx.update(&plain);
        Bytes::copy_from_slice(ctx.sign().as_ref())
    }
}

pub(crate) struct HmacSha1 {
    key: Key,
}

impl HmacSha1 {
    pub fn new(key: &Bytes) -> Self {
        let key = Key::new(HMAC_SHA1, &key.clone().split_to(20)); // TODO
        Self { key }
    }
}

impl MacType for HmacSha1 {
    fn size(&self) -> usize {
        20
    }
    fn name(&self) -> &'static str {
        "hmac-sha1"
    }
    fn sign(&self, seq: u32, plain: &Bytes, _encrypted: &Bytes) -> Bytes {
        let mut ctx = Context::with_key(&self.key);
        ctx.update(&seq.to_be_bytes());
        ctx.update(&plain);
        Bytes::copy_from_slice(ctx.sign().as_ref())
    }
}

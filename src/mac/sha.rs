use bytes::Bytes;
use ring::hmac::{Context, Key, HMAC_SHA256};

use super::{Mac, MacResult};

pub struct HmacSha2_256 {
    key: Key,
}

impl HmacSha2_256 {
    pub fn new(key: &Bytes) -> Self {
        let key = Key::new(HMAC_SHA256, &key);
        Self { key }
    }
}

impl Mac for HmacSha2_256 {
    fn size(&self) -> usize {
        32
    }
    fn name(&self) -> &'static str {
        "hmac-sha2-256"
    }
    fn sign(&self, seq: u32, plain: &Bytes, _encrypted: &Bytes) -> MacResult<Bytes> {
        let mut ctx = Context::with_key(&self.key);
        ctx.update(&seq.to_be_bytes());
        ctx.update(&plain);
        Ok(Bytes::from(ctx.sign().as_ref()))
    }
}

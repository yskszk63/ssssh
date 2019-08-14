use bytes::Bytes;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::sign::Signer;

use super::{Mac, MacResult};

pub struct HmacSha2_256 {
    key: PKey<Private>,
}

impl HmacSha2_256 {
    pub fn new(key: &Bytes) -> Self {
        let key = PKey::hmac(&key).unwrap();
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
        let mut signer = Signer::new(MessageDigest::sha256(), &self.key).unwrap();
        signer
            .update(&[
                (seq >> 24) as u8,
                (seq >> 16) as u8,
                (seq >> 8) as u8,
                (seq >> 0) as u8,
            ])
            .unwrap();
        signer.update(&plain).unwrap();
        Ok(Bytes::from(signer.sign_to_vec().unwrap()))
    }
}

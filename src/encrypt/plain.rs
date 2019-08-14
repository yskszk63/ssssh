use bytes::Bytes;

use super::{Encrypt, EncryptResult};

pub struct PlainEncrypt;

impl Encrypt for PlainEncrypt {
    fn name(&self) -> &'static str {
        "plain"
    }
    fn block_size(&self) -> usize {
        8
    }
    fn encrypt(&mut self, pkt: &Bytes) -> EncryptResult<Bytes> {
        Ok(pkt.clone())
    }
}

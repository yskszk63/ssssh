//! `none` encrypt
use super::*;

/// `none` encrypt
#[derive(Debug)]
pub struct None {}

impl None {
    pub(super) fn new() -> Self {
        Self {}
    }
}

impl EncryptTrait for None {
    const NAME: &'static str = "none";
    const BLOCK_SIZE: usize = 8;
    const KEY_LENGTH: usize = 0;

    fn new_for_encrypt(_key: &[u8], _iv: &[u8]) -> Result<Self, EncryptError> {
        Ok(Self::new())
    }

    fn new_for_decrypt(_key: &[u8], _iv: &[u8]) -> Result<Self, EncryptError> {
        Ok(Self::new())
    }

    fn update(&mut self, src: &[u8], dst: &mut BytesMut) -> Result<(), EncryptError> {
        dst.extend_from_slice(src);
        Ok(())
    }
}

impl From<None> for Encrypt {
    fn from(v: None) -> Self {
        Self::None(v)
    }
}

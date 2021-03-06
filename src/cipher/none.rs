//! `none` cipher
use super::*;

/// `none` cipher
#[derive(Debug)]
pub struct None {}

impl None {
    pub(super) fn new() -> Self {
        Self {}
    }
}

impl CipherTrait for None {
    const BLOCK_SIZE: usize = 8;
    const KEY_LENGTH: usize = 0;

    fn new_for_encrypt(_key: &[u8], _iv: &[u8]) -> Result<Self, SshError> {
        Ok(Self::new())
    }

    fn new_for_decrypt(_key: &[u8], _iv: &[u8]) -> Result<Self, SshError> {
        Ok(Self::new())
    }

    fn update(&mut self, _target: &mut [u8]) -> Result<(), SshError> {
        Ok(())
    }
}

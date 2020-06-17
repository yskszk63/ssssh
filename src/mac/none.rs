use super::*;

#[derive(Debug)]
pub(crate) struct None {}

impl MacTrait for None {
    const NAME: Algorithm = Algorithm::None;
    const LEN: usize = 0;

    fn new(_key: &[u8]) -> Self {
        Self {}
    }

    fn sign(&self, _seq: u32, _plain: &[u8]) -> Result<Bytes, SshError> {
        Ok(Bytes::new())
    }

    fn verify(&self, _seq: u32, _plain: &[u8], _tag: &[u8]) -> Result<(), SshError> {
        Ok(())
    }
}

impl From<None> for Mac {
    fn from(v: None) -> Self {
        Self::None(v)
    }
}

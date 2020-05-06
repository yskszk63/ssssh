use bytes::buf::Buf as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

use super::*;

#[derive(Debug)]
pub(crate) struct Ed25519 {
    pair: Ed25519KeyPair,
}

impl HostKeyTrait for Ed25519 {
    const NAME: &'static str = "ssh-ed25519";

    fn gen() -> Result<Self, GenError> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
            .map_err(|e| GenError::Err(Box::new(e)))?;
        let pair =
            Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(|e| GenError::Err(Box::new(e)))?;
        Ok(Self { pair })
    }

    fn publickey(&self) -> Bytes {
        let mut b = BytesMut::new();
        self.pair.public_key().as_ref().to_bytes().pack(&mut b);
        b.freeze()
    }

    fn sign(&self, target: &Bytes) -> Bytes {
        let sign = self.pair.sign(target.as_ref());
        sign.as_ref().to_bytes()
    }
}

impl From<Ed25519> for HostKey {
    fn from(v: Ed25519) -> Self {
        Self::Ed25519(v)
    }
}

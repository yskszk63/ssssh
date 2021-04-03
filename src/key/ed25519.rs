use std::fmt;

use bytes::buf::Buf as _;
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _, UnparsedPublicKey, ED25519};

use super::*;

#[derive(Debug)]
pub(crate) struct Ed25519 {
    pair: Ed25519KeyPair,
}

impl KeyTrait for Ed25519 {
    const NAME: Algorithm = Algorithm::SshEd25519;

    fn gen() -> Result<Self, SshError> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).map_err(SshError::any)?;
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).map_err(SshError::any)?;
        Ok(Self { pair })
    }

    fn parse(mut buf: &[u8]) -> Result<Self, SshError> {
        let pk = Bytes::unpack(&mut buf)?;
        let sk = Bytes::unpack(&mut buf)?;
        let pair =
            Ed25519KeyPair::from_seed_and_public_key(&sk[..32], &pk).map_err(SshError::any)?;
        Ok(Self { pair })
    }

    fn publickey(&self) -> Bytes {
        let mut b = BytesMut::new();
        let public_key = self.pair.public_key();
        let mut public_key = public_key.as_ref();
        public_key
            .copy_to_bytes(public_key.remaining())
            .pack(&mut b);
        b.freeze()
    }

    fn sign(&self, target: &Bytes) -> Bytes {
        let sign = self.pair.sign(target.as_ref());
        let mut sign = sign.as_ref();
        sign.copy_to_bytes(sign.remaining())
    }
}

impl From<Ed25519> for Key {
    fn from(v: Ed25519) -> Self {
        Self::Ed25519(v)
    }
}

pub(crate) struct Ed25519Verifier {
    pk: UnparsedPublicKey<Bytes>,
    buf: BytesMut,
}

impl VerifierTrait for Ed25519Verifier {
    const NAME: Algorithm = Algorithm::SshEd25519;

    fn new(pk: &[u8]) -> Result<Self, SshError> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(pk);
        let pk = Bytes::unpack(&mut buf)?;
        let pk = UnparsedPublicKey::new(&ED25519, pk);
        Ok(Self {
            pk,
            buf: BytesMut::new(),
        })
    }

    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn verify(&self, signature: &[u8]) -> bool {
        self.pk.verify(&self.buf, signature).is_ok()
    }
}

impl fmt::Debug for Ed25519Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ED25519Verifier")
    }
}

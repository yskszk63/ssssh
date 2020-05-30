use std::fmt;

use openssl::bn::BigNum;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::{Padding, Rsa as OpenSslRsa};
use openssl::sign::Signer;
use openssl::sign::Verifier;

use super::*;
use crate::pack::Mpint;

#[derive(Debug)]
pub(crate) struct Rsa {
    pair: OpenSslRsa<Private>,
}

impl HostKeyTrait for Rsa {
    const NAME: &'static str = "ssh-rsa";

    fn gen() -> Result<Self, SshError> {
        let pair = OpenSslRsa::generate(2048).map_err(SshError::any)?;
        Ok(Self { pair })
    }

    fn publickey(&self) -> Bytes {
        let mut b = BytesMut::new();
        Mpint::new(self.pair.e().to_vec()).pack(&mut b);
        Mpint::new(self.pair.n().to_vec()).pack(&mut b);
        b.freeze()
    }

    fn sign(&self, target: &Bytes) -> Bytes {
        let pkey = PKey::from_rsa(self.pair.clone()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha1(), &pkey).unwrap();
        signer.set_rsa_padding(Padding::PKCS1).unwrap();
        signer.update(target.as_ref()).unwrap();
        signer.sign_to_vec().unwrap().into()
    }
}

impl From<Rsa> for HostKey {
    fn from(v: Rsa) -> Self {
        Self::Rsa(v)
    }
}

pub(crate) struct RsaVerifier {
    key: PKey<Public>,
    buf: BytesMut,
}

impl VerifierTrait for RsaVerifier {
    const NAME: &'static str = "ssh-rsa";

    fn new(pk: &[u8]) -> Self {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(pk);

        let e = Bytes::unpack(&mut buf).unwrap();
        let n = Bytes::unpack(&mut buf).unwrap();

        let e = BigNum::from_slice(&e).unwrap();
        let n = BigNum::from_slice(&n).unwrap();

        let key = OpenSslRsa::from_public_components(n, e).unwrap();
        let key = PKey::from_rsa(key).unwrap();

        Self {
            key,
            buf: BytesMut::new(),
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn verify(&self, signature: &[u8]) -> bool {
        let mut verifier = Verifier::new(MessageDigest::sha1(), &self.key).unwrap();
        verifier.set_rsa_padding(Padding::PKCS1).unwrap();
        verifier.update(&self.buf).unwrap();
        verifier.verify(signature).unwrap()
    }
}

impl fmt::Debug for RsaVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RsaVerifier")
    }
}

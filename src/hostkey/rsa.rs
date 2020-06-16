use std::fmt;

use openssl::bn::{BigNum, BigNumContext};
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
    const NAME: Algorithm = Algorithm::SshRsa;

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

    #[allow(clippy::many_single_char_names)]
    fn parse(mut buf: &[u8]) -> Result<Self, SshError> {
        let n = BigNum::from_slice(&Bytes::unpack(&mut buf)?).map_err(SshError::any)?;
        let e = BigNum::from_slice(&Bytes::unpack(&mut buf)?).map_err(SshError::any)?;
        let d = BigNum::from_slice(&Bytes::unpack(&mut buf)?).map_err(SshError::any)?;
        let iqmp = BigNum::from_slice(&Bytes::unpack(&mut buf)?).map_err(SshError::any)?;
        let p = BigNum::from_slice(&Bytes::unpack(&mut buf)?).map_err(SshError::any)?;
        let q = BigNum::from_slice(&Bytes::unpack(&mut buf)?).map_err(SshError::any)?;

        let mut cx = BigNumContext::new().map_err(SshError::any)?;
        let mut aux = BigNum::new().map_err(SshError::any)?;
        let mut dmq1 = BigNum::new().map_err(SshError::any)?;
        let mut dmp1 = BigNum::new().map_err(SshError::any)?;

        let consttime = (&d).to_owned(); // BN_dup

        aux.checked_sub(&q, BigNum::from_u32(1).map_err(SshError::any)?.as_ref())
            .map_err(SshError::any)?;
        dmq1.nnmod(&consttime, &aux, &mut cx)
            .map_err(SshError::any)?;
        aux.checked_sub(&p, BigNum::from_u32(1).map_err(SshError::any)?.as_ref())
            .map_err(SshError::any)?;
        dmp1.nnmod(&consttime, &aux, &mut cx)
            .map_err(SshError::any)?;

        let pair = OpenSslRsa::from_private_components(n, e, d, p, q, dmp1, dmq1, iqmp)
            .map_err(SshError::any)?;
        Ok(Self { pair })
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
    const NAME: Algorithm = Algorithm::SshRsa;

    fn new(pk: &[u8]) -> Result<Self, SshError> {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(pk);

        let e = Bytes::unpack(&mut buf)?;
        let n = Bytes::unpack(&mut buf)?;

        let e = BigNum::from_slice(&e).map_err(SshError::any)?;
        let n = BigNum::from_slice(&n).map_err(SshError::any)?;

        let key = OpenSslRsa::from_public_components(n, e).map_err(SshError::any)?;
        let key = PKey::from_rsa(key).map_err(SshError::any)?;

        Ok(Self {
            key,
            buf: BytesMut::new(),
        })
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

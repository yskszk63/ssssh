//! key algorithms
use std::fmt;
use std::str::FromStr;

use base64::display::Base64Display;
use base64::{CharacterSet, Config};
use bytes::{Buf, Bytes, BytesMut};

use crate::negotiate::{AlgorithmName, UnknownNameError};
use crate::pack::{Pack, Put, Unpack, UnpackError};
use crate::SshError;

mod ed25519;
mod rsa;

/// SSH key algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// `ssh-ed25519`
    SshEd25519,

    /// `ssh-rsa`
    SshRsa,
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        match self {
            Self::SshEd25519 => "ssh-ed25519",
            Self::SshRsa => "ssh-rsa",
        }
    }
}

impl FromStr for Algorithm {
    type Err = UnknownNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ssh-ed25519" => Ok(Self::SshEd25519),
            "ssh-rsa" => Ok(Self::SshRsa),
            x => Err(UnknownNameError(x.into())),
        }
    }
}

impl AlgorithmName for Algorithm {
    fn defaults() -> Vec<Self> {
        vec![Self::SshEd25519, Self::SshRsa]
    }
}

/// Sign by key
#[derive(Debug, Clone)]
pub(crate) struct Signature(String, Bytes);

impl Pack for Signature {
    fn pack<P: Put>(&self, buf: &mut P) {
        let mut b = BytesMut::new();
        self.0.pack(&mut b);
        self.1.pack(&mut b);

        b.freeze().pack(buf)
    }
}

impl Unpack for Signature {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let mut buf = Bytes::unpack(buf)?;
        let name = Unpack::unpack(&mut buf)?;
        let sig = Unpack::unpack(&mut buf)?;
        Ok(Self(name, sig))
    }
}

trait VerifierTrait: Sized {
    const NAME: Algorithm;

    fn new(pk: &[u8]) -> Result<Self, SshError>;

    fn update(&mut self, data: &[u8]);

    fn verify(&self, signature: &[u8]) -> bool;
}

#[derive(Debug)]
pub(crate) enum Verifier {
    Ed25519(ed25519::Ed25519Verifier),
    Rsa(rsa::RsaVerifier),
}

impl Verifier {
    fn new(name: &str, pk: &[u8]) -> Result<Self, SshError> {
        match Algorithm::from_str(name) {
            Ok(Algorithm::SshEd25519) => Ok(Self::Ed25519(ed25519::Ed25519Verifier::new(pk)?)),
            Ok(Algorithm::SshRsa) => Ok(Self::Rsa(rsa::RsaVerifier::new(pk)?)),
            Err(x) => Err(SshError::UnknownAlgorithm(x.0)),
        }
    }

    pub(crate) fn verify(&self, signature: &Signature) -> bool {
        match self {
            Self::Ed25519(item) => item.verify(&signature.1),
            Self::Rsa(item) => item.verify(&signature.1),
        }
    }
}

impl Put for Verifier {
    fn put(&mut self, src: &[u8]) {
        match self {
            Self::Ed25519(item) => item.update(src),
            Self::Rsa(item) => item.update(src),
        }
    }
}

/// Public key
#[derive(Debug, Clone)]
pub(crate) struct PublicKey(String, Bytes);

impl PublicKey {
    pub(crate) fn verifier(self) -> Result<Verifier, SshError> {
        Verifier::new(&self.0, &self.1)
    }
}

impl Pack for PublicKey {
    fn pack<P: Put>(&self, buf: &mut P) {
        let mut b = BytesMut::new();
        self.0.pack(&mut b);
        b.extend_from_slice(&self.1);

        b.freeze().pack(buf)
    }
}

impl Unpack for PublicKey {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let mut buf = Bytes::unpack(buf)?;
        let name = Unpack::unpack(&mut buf)?;
        let data = buf.to_bytes();
        Ok(Self(name, data))
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut buf = BytesMut::new();
        self.0.pack(&mut buf);
        buf.extend_from_slice(&self.1);
        write!(
            f,
            "{} {}",
            self.0,
            Base64Display::with_config(&buf, Config::new(CharacterSet::Standard, false))
        )
    }
}

/// Key algorithm trait
pub(crate) trait KeyTrait: Into<Key> + Sized {
    /// Hostkey algorithm name
    const NAME: Algorithm;

    /// Generate hostkey
    fn gen() -> Result<Self, SshError>;

    /// Get hostkey's public key
    fn publickey(&self) -> Bytes;

    /// Sign by hostkey
    fn sign(&self, target: &Bytes) -> Bytes;

    fn parse(buf: &[u8]) -> Result<Self, SshError>;
}

/// Hostkey algorithms
#[derive(Debug)]
pub(crate) enum Key {
    /// ssh-ed25519
    Ed25519(ed25519::Ed25519),

    /// ssh-rsa
    Rsa(rsa::Rsa),
}

impl Key {
    /// Generate hostkey by algorithm name
    pub(crate) fn gen(name: &Algorithm) -> Result<Self, SshError> {
        match name {
            Algorithm::SshEd25519 => Ok(ed25519::Ed25519::gen()?.into()),
            Algorithm::SshRsa => Ok(rsa::Rsa::gen()?.into()),
        }
    }

    pub(crate) fn parse(name: &Algorithm, data: &[u8]) -> Result<Self, SshError> {
        match name {
            Algorithm::SshEd25519 => Ok(ed25519::Ed25519::parse(data)?.into()),
            Algorithm::SshRsa => Ok(rsa::Rsa::parse(data)?.into()),
        }
    }

    /// Hostkey algorithm name
    pub(crate) fn name(&self) -> Algorithm {
        match self {
            Self::Ed25519(..) => ed25519::Ed25519::NAME,
            Self::Rsa(..) => rsa::Rsa::NAME,
        }
    }

    /// Get hostkey's public key
    pub(crate) fn publickey(&self) -> PublicKey {
        let name = self.name().as_ref().into();
        match self {
            Self::Ed25519(item) => PublicKey(name, item.publickey()),
            Self::Rsa(item) => PublicKey(name, item.publickey()),
        }
    }

    /// Sign by hostkey
    pub(crate) fn sign(&self, target: &Bytes) -> Signature {
        let name = self.name().as_ref().into();
        match self {
            Self::Ed25519(item) => Signature(name, item.sign(target)),
            Self::Rsa(item) => Signature(name, item.sign(target)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<Key>();
        assert::<PublicKey>();
        assert::<Signature>();
    }

    #[test]
    fn test_signature() {
        let b = Bytes::from("Hello, World!");
        let k = Key::gen(&Algorithm::SshEd25519).unwrap();
        let sign = k.sign(&b);

        let mut b = BytesMut::new();
        sign.pack(&mut b);
        Signature::unpack(&mut b).unwrap();
    }

    #[test]
    fn test_publickey() {
        let k = Key::gen(&Algorithm::SshEd25519).unwrap();
        let pubkey = k.publickey();

        let mut b = BytesMut::new();
        pubkey.pack(&mut b);
        PublicKey::unpack(&mut b).unwrap();
    }

    #[test]
    fn test_ed25519() {
        use ring::signature::*;

        let b = Bytes::from("Hello, World!");
        let k = Key::gen(&Algorithm::SshEd25519).unwrap();
        let sign = k.sign(&b).1;
        let pubkey = Bytes::unpack(&mut k.publickey().1).unwrap();

        let pubkey = UnparsedPublicKey::new(&ED25519, &pubkey);
        pubkey.verify(&b, &sign).unwrap();
    }

    #[test]
    fn test_rsa() {
        use openssl::bn::BigNum;
        use openssl::hash::MessageDigest;
        use openssl::pkey::PKey;
        use openssl::rsa::Rsa;
        use openssl::sign::Verifier;

        let b = Bytes::from("Hello, World!");
        let k = Key::gen(&Algorithm::SshRsa).unwrap();
        let sign = k.sign(&b).1;

        let mut pubkey = k.publickey().1;
        let e = Bytes::unpack(&mut pubkey).unwrap();
        let n = Bytes::unpack(&mut pubkey).unwrap();
        let e = BigNum::from_slice(&e).unwrap();
        let n = BigNum::from_slice(&n).unwrap();
        let pubkey = Rsa::from_public_components(n, e).unwrap();
        let pubkey = PKey::from_rsa(pubkey).unwrap();

        let verifier = Verifier::new(MessageDigest::sha1(), &pubkey).unwrap();
        verifier.verify(&sign).unwrap();
    }

    #[test]
    fn test_parse() {
        for name in Algorithm::defaults() {
            let s = name.as_ref();
            let a = Algorithm::from_str(s).unwrap();
            assert_eq!(name, a);
        }

        Algorithm::from_str("").unwrap_err();
    }
}

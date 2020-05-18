//! Hostkey algorithms
use std::error::Error as StdError;

use bytes::{Buf, Bytes, BytesMut};
use linked_hash_map::LinkedHashMap;
use thiserror::Error;

use crate::pack::{Pack, Put, Unpack, UnpackError};

mod ed25519;
mod rsa;

/// HostKey collection
#[derive(Debug)]
pub(crate) struct HostKeys {
    hostkeys: LinkedHashMap<String, HostKey>,
}

impl HostKeys {
    pub(crate) fn new() -> Self {
        Self {
            hostkeys: LinkedHashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, hostkey: HostKey) {
        self.hostkeys.insert(hostkey.name().to_string(), hostkey);
    }

    pub(crate) fn lookup(&self, name: &str) -> Option<&HostKey> {
        self.hostkeys.get(name)
    }

    pub(crate) fn names(&self) -> Vec<String> {
        self.hostkeys.keys().map(ToString::to_string).collect()
    }

    // TODO implement gen and load public interface
}

/// Sign by hostkey
#[derive(Debug)]
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

/// Hostkey's public key
#[derive(Debug)]
pub(crate) struct PublicKey(String, Bytes);

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

/// Hostkey generate error
#[derive(Debug, Error)]
pub(crate) enum GenError {
    #[error(transparent)]
    Err(#[from] Box<dyn StdError + Send + Sync + 'static>),

    #[error("unknown hostkey algorithm {0}")]
    UnknownHostkeyAlgorithm(String),
}

/// Hostkey algorithm trait
pub(crate) trait HostKeyTrait: Into<HostKey> + Sized {
    /// Hostkey algorithm name
    const NAME: &'static str;

    /// Generate hostkey
    fn gen() -> Result<Self, GenError>;

    /// Get hostkey's public key
    fn publickey(&self) -> Bytes;

    /// Sign by hostkey
    fn sign(&self, target: &Bytes) -> Bytes;
}

/// Hostkey algorithms
#[derive(Debug)]
pub(crate) enum HostKey {
    /// ssh-ed25519
    Ed25519(ed25519::Ed25519),

    /// ssh-rsa
    Rsa(rsa::Rsa),
}

impl HostKey {
    /// Generate hostkey by algorithm name
    pub(crate) fn gen(name: &str) -> Result<Self, GenError> {
        Ok(match name {
            ed25519::Ed25519::NAME => ed25519::Ed25519::gen()?.into(),
            rsa::Rsa::NAME => rsa::Rsa::gen()?.into(),
            v => return Err(GenError::UnknownHostkeyAlgorithm(v.into())),
        })
    }

    /// Hostkey algorithm name
    pub(crate) fn name(&self) -> &str {
        match self {
            Self::Ed25519(..) => ed25519::Ed25519::NAME,
            Self::Rsa(..) => rsa::Rsa::NAME,
        }
    }

    /// Get hostkey's public key
    pub(crate) fn publickey(&self) -> PublicKey {
        match self {
            Self::Ed25519(item) => PublicKey(ed25519::Ed25519::NAME.to_string(), item.publickey()),
            Self::Rsa(item) => PublicKey(rsa::Rsa::NAME.to_string(), item.publickey()),
        }
    }

    /// Sign by hostkey
    pub(crate) fn sign(&self, target: &Bytes) -> Signature {
        match self {
            Self::Ed25519(item) => Signature(ed25519::Ed25519::NAME.to_string(), item.sign(target)),
            Self::Rsa(item) => Signature(rsa::Rsa::NAME.to_string(), item.sign(target)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<HostKeys>();
        assert::<HostKey>();
        assert::<PublicKey>();
        assert::<Signature>();
    }

    #[test]
    fn test_unknown() {
        HostKey::gen("-").unwrap_err();
    }

    #[test]
    fn test_signature() {
        let b = Bytes::from("Hello, World!");
        let k = HostKey::gen("ssh-ed25519").unwrap();
        let sign = k.sign(&b);

        let mut b = BytesMut::new();
        sign.pack(&mut b);
        Signature::unpack(&mut b).unwrap();
    }

    #[test]
    fn test_publickey() {
        let k = HostKey::gen("ssh-ed25519").unwrap();
        let pubkey = k.publickey();

        let mut b = BytesMut::new();
        pubkey.pack(&mut b);
        PublicKey::unpack(&mut b).unwrap();
    }

    #[test]
    fn test_ed25519() {
        use ring::signature::*;

        let b = Bytes::from("Hello, World!");
        let k = HostKey::gen("ssh-ed25519").unwrap();
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
        let k = HostKey::gen("ssh-rsa").unwrap();
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
}
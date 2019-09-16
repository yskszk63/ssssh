use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use failure::Fail;
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa};
use openssl::sign::Signer;
use ring::error::{KeyRejected, Unspecified};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

use crate::algorithm::HostKeyAlgorithm;
use crate::named::Named as _;
use crate::sshbuf::SshBufMut;

#[derive(Debug, Clone)]
pub struct HostKeys {
    keys: Vec<HostKey>,
}

impl HostKeys {
    pub fn new(keys: impl IntoIterator<Item = HostKey>) -> Self {
        let keys = keys.into_iter().collect();
        Self { keys }
    }

    pub(crate) fn lookup(&self, algorithm: &HostKeyAlgorithm) -> Option<&HostKey> {
        self.keys.iter().find(|k| &k.algorithm() == algorithm)
    }
}

#[derive(Debug, Fail)]
pub enum GenError {
    #[fail(display = "Unspecified")]
    Unspecified(Unspecified),
    #[fail(display = "KeyRejected")]
    KeyRejected(KeyRejected),
    #[fail(display = "ErrorStack")]
    ErrorStack(ErrorStack),
}

impl From<Unspecified> for GenError {
    fn from(v: Unspecified) -> Self {
        Self::Unspecified(v)
    }
}

impl From<KeyRejected> for GenError {
    fn from(v: KeyRejected) -> Self {
        Self::KeyRejected(v)
    }
}

impl From<ErrorStack> for GenError {
    fn from(v: ErrorStack) -> Self {
        Self::ErrorStack(v)
    }
}

pub type GenResult<T> = Result<T, GenError>;

#[derive(Debug, Clone)]
pub enum HostKey {
    SshEd25519 {
        pair: Arc<Ed25519KeyPair>,
        public: Bytes,
    },
    SshRsa {
        pair: Arc<Rsa<Private>>,
        public: Bytes,
    },
}

impl HostKey {
    pub fn gen_ssh_ed25519() -> GenResult<Self> {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())?;
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())?;
        let public = Bytes::from(pair.public_key().as_ref());
        Ok(Self::SshEd25519 {
            pair: Arc::new(pair),
            public,
        })
    }

    pub fn gen_ssh_rsa(n: u32) -> GenResult<Self> {
        let pair = Rsa::generate(n)?;
        let public = Bytes::from(PKey::from_rsa(pair.clone()).unwrap().public_key_to_der()?);
        Ok(Self::SshRsa {
            pair: Arc::new(pair),
            public,
        })
    }

    pub fn algorithm(&self) -> HostKeyAlgorithm {
        match self {
            Self::SshEd25519 { .. } => HostKeyAlgorithm::SshEd25519,
            Self::SshRsa { .. } => HostKeyAlgorithm::SshRsa,
        }
    }

    pub(crate) fn put_to(&self, buf: &mut impl SshBufMut) {
        buf.put_binary_string(&{
            match self {
                Self::SshEd25519 { pair, .. } => {
                    let name = self.algorithm().name();
                    let mut buf = BytesMut::with_capacity(name.len() + 4 + 32 + 4);
                    buf.put_string(name);
                    let pair = pair.as_ref();
                    buf.put_binary_string(&pair.public_key().as_ref());
                    buf
                }
                Self::SshRsa { pair, .. } => {
                    let pair = pair.as_ref();

                    let name = self.algorithm().name();
                    let mut buf = BytesMut::with_capacity(name.len() + 4 + 32 + 4);
                    buf.put_string(name);
                    //buf.put_binary_string(&pair.public_key_to_der().unwrap());
                    buf.put_mpint(&pair.e().to_vec());
                    buf.put_mpint(&pair.n().to_vec());
                    buf
                }
            }
        })
    }

    pub(crate) fn sign(&self, target: &[u8]) -> Signature {
        match self {
            Self::SshEd25519 { pair, .. } => {
                let pair = pair.as_ref();
                let sign = pair.sign(target);
                Signature::SshEd25519(Bytes::from(sign.as_ref()))
            }
            Self::SshRsa { pair, .. } => {
                let pair = pair.as_ref();
                let pkey = PKey::from_rsa(pair.clone()).unwrap();
                let mut signer = Signer::new(MessageDigest::sha1(), &pkey).unwrap();
                signer.set_rsa_padding(Padding::PKCS1).unwrap();
                signer.update(target).unwrap();
                Signature::SshRsa(Bytes::from(signer.sign_to_vec().unwrap()))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Signature {
    SshEd25519(Bytes),
    SshRsa(Bytes),
}

impl Signature {
    pub fn algorithm(&self) -> HostKeyAlgorithm {
        match self {
            Self::SshEd25519(..) => HostKeyAlgorithm::SshEd25519,
            Self::SshRsa(..) => HostKeyAlgorithm::SshRsa,
        }
    }

    pub(crate) fn put_to(&self, buf: &mut impl SshBufMut) {
        buf.put_binary_string(&{
            let mut buf = BytesMut::new();
            let name = self.algorithm().name();
            buf.put_string(name);

            match self {
                Self::SshEd25519(sig) => {
                    buf.put_binary_string(&sig);
                }
                Self::SshRsa(sig) => {
                    buf.put_binary_string(&sig);
                }
            }
            buf
        })
    }
}

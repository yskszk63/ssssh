use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

use crate::algorithm::HostKeyAlgorithm;
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

    pub fn lookup(&self, algorithm: &HostKeyAlgorithm) -> Option<&HostKey> {
        self.keys.iter().find(|k| &k.algorithm() == algorithm)
    }
}

#[derive(Debug)]
pub enum SignError {}

pub type SignResult<T> = Result<T, SignError>;

#[derive(Debug, Clone)]
pub enum HostKey {
    SshEd25519 {
        pair: Arc<Ed25519KeyPair>,
        public: Bytes,
    },
}

impl HostKey {
    pub fn gen_ssh_ed25519() -> Self {
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let public = Bytes::from(pair.public_key().as_ref());
        Self::SshEd25519 {
            pair: Arc::new(pair),
            public,
        }
    }

    pub fn publickey(&self) -> &Bytes {
        match self {
            Self::SshEd25519 { public, .. } => &public,
        }
    }

    pub fn algorithm(&self) -> HostKeyAlgorithm {
        match self {
            Self::SshEd25519 { .. } => HostKeyAlgorithm::SshEd25519,
        }
    }

    pub(crate) fn put_to(&self, buf: &mut impl SshBufMut) {
        buf.put_binary_string(&{
            match self {
                Self::SshEd25519 { pair, .. } => {
                    let name = "ssh-ed25519";
                    let mut buf = BytesMut::with_capacity(name.len() + 4 + 32 + 4);
                    buf.put_string(name);
                    let pair = pair.as_ref();
                    buf.put_binary_string(&pair.public_key().as_ref());
                    buf
                }
            }
        })
    }

    pub fn sign(&self, target: &[u8]) -> SignResult<Bytes> {
        match self {
            Self::SshEd25519 { pair, .. } => {
                let pair = pair.as_ref();
                let sign = pair.sign(target);
                Ok(Bytes::from(sign.as_ref()))
            }
        }
    }
}

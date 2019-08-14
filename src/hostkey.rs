use bytes::{Bytes, BytesMut};
use sodiumoxide::crypto::sign::ed25519::{gen_keypair, sign_detached};

use crate::algorithm::HostKeyAlgorithm;
use crate::sshbuf::{SshBufMut, SshBufResult};

#[derive(Debug)]
pub struct HostKeys {
    keys: Vec<HostKey>,
}

impl HostKeys {
    pub fn new(keys: impl IntoIterator<Item = HostKey>) -> Self {
        let keys = keys.into_iter().collect();
        Self { keys }
    }

    pub fn lookup(&self, algorithm: &HostKeyAlgorithm) -> Option<&HostKey> {
        self.keys
            .iter()
            .filter(|k| &k.algorithm() == algorithm)
            .next()
    }
}

#[derive(Debug)]
pub enum SignError {}

pub type SignResult<T> = Result<T, SignError>;

#[derive(Debug)]
pub enum HostKey {
    SshEd25519 { secret: Bytes, public: Bytes },
}

impl HostKey {
    pub fn gen_ssh_ed25519() -> Self {
        let (public, secret) = gen_keypair();

        let public = Bytes::from(&public.0[..]);
        let secret = Bytes::from(&secret.0[..]);

        HostKey::SshEd25519 { public, secret }
    }

    pub fn secretkey(&self) -> &Bytes {
        match self {
            HostKey::SshEd25519 { ref secret, .. } => secret,
        }
    }

    pub fn publickey(&self) -> &Bytes {
        match self {
            HostKey::SshEd25519 { public, .. } => public,
        }
    }

    pub fn algorithm(&self) -> HostKeyAlgorithm {
        match self {
            HostKey::SshEd25519 { .. } => HostKeyAlgorithm::SshEd25519,
        }
    }

    pub fn put_to(&self, buf: &mut impl SshBufMut) -> SshBufResult<()> {
        buf.put_binary_string(&{
            match self {
                HostKey::SshEd25519 { public, .. } => {
                    let name = "ssh-ed25519";
                    let mut buf = BytesMut::with_capacity(name.len() + 4 + 32 + 4);
                    buf.put_string(name)?;
                    buf.put_binary_string(&public)?;
                    buf
                }
            }
        })
    }

    pub fn sign(&self, target: &[u8]) -> SignResult<Bytes> {
        match self {
            HostKey::SshEd25519 { secret, .. } => {
                let secret =
                    sodiumoxide::crypto::sign::ed25519::SecretKey::from_slice(secret).unwrap();
                let sign = sign_detached(target, &secret);
                Ok(Bytes::from(&sign.0[..]))
            }
        }
    }
}

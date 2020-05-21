use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::hostkey::HostKey;
use crate::msg::kexinit::Kexinit;
use crate::msg::Msg;
use crate::pack::Pack;
use crate::stream::msg::{MsgStream, RecvError, SendError};

mod curve25519;
mod diffie_hellman;

#[derive(Debug)]
struct Env<'a> {
    c_version: &'a str,
    s_version: &'a str,
    c_kexinit: &'a Bytes,
    s_kexinit: &'a Bytes,
    hostkey: &'a HostKey,
}

#[derive(Debug, Error)]
pub enum KexError {
    #[error("unexpected msg {0:}")]
    UnexpectedMsg(String),

    #[error("unexpected eof")]
    UnexpectedEof,

    #[error("unknown kex algorithm {0}")]
    UnknownKexAlgorithm(String),

    #[error(transparent)]
    RecvError(#[from] RecvError),

    #[error(transparent)]
    SendError(#[from] SendError),

    #[error("{0:?}")]
    Any(String),
}

#[async_trait]
trait KexTrait: Sized + Into<Kex> {
    const NAME: &'static str;

    fn new() -> Self;

    fn hash<B: Buf>(buf: &B) -> Bytes;

    async fn kex<IO>(
        &self,
        io: &mut MsgStream<IO>,
        env: Env<'_>,
    ) -> Result<(Bytes, Bytes), KexError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send;
}

fn to_msg_bytes(kexinit: &Kexinit) -> Bytes {
    let msg = Msg::from(kexinit.clone());
    let mut b = BytesMut::new();
    msg.pack(&mut b);
    b.freeze()
}

#[derive(Debug)]
pub(crate) enum Kex {
    Curve25519Sha256(curve25519::Curve25519Sha256),
    DiffieHellmanGroup14Sha1(diffie_hellman::DiffieHellmanGroup14Sha1),
    DiffieHellmanGroupExchangeSha256(diffie_hellman::DiffieHellmanGroupExchangeSha256),
}

impl Kex {
    pub(crate) fn defaults() -> Vec<String> {
        vec![
            curve25519::Curve25519Sha256::NAME.to_string(),
            diffie_hellman::DiffieHellmanGroup14Sha1::NAME.to_string(),
            diffie_hellman::DiffieHellmanGroupExchangeSha256::NAME.to_string(),
        ]
    }

    pub(crate) fn hash<B: Buf>(&self, buf: &B) -> Bytes {
        match self {
            Self::Curve25519Sha256(..) => curve25519::Curve25519Sha256::hash(buf),
            Self::DiffieHellmanGroup14Sha1(..) => {
                diffie_hellman::DiffieHellmanGroup14Sha1::hash(buf)
            }
            Self::DiffieHellmanGroupExchangeSha256(..) => {
                diffie_hellman::DiffieHellmanGroupExchangeSha256::hash(buf)
            }
        }
    }

    pub(crate) fn new(name: &str) -> Result<Self, KexError> {
        Ok(match name {
            curve25519::Curve25519Sha256::NAME => curve25519::Curve25519Sha256::new().into(),
            diffie_hellman::DiffieHellmanGroup14Sha1::NAME => {
                diffie_hellman::DiffieHellmanGroup14Sha1::new().into()
            }
            diffie_hellman::DiffieHellmanGroupExchangeSha256::NAME => {
                diffie_hellman::DiffieHellmanGroupExchangeSha256::new().into()
            }
            v => return Err(KexError::UnknownKexAlgorithm(v.to_string())),
        })
    }

    pub(crate) async fn kex<IO>(
        &self,
        io: &mut MsgStream<IO>,
        c_version: &str,
        s_version: &str,
        c_kexinit: &Kexinit,
        s_kexinit: &Kexinit,
        hostkey: &HostKey,
    ) -> Result<(Bytes, Bytes), KexError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let c_kexinit = to_msg_bytes(c_kexinit);
        let s_kexinit = to_msg_bytes(s_kexinit);
        let env = Env {
            c_version,
            s_version,
            c_kexinit: &c_kexinit,
            s_kexinit: &s_kexinit,
            hostkey,
        };

        Ok(match self {
            Self::Curve25519Sha256(item) => item.kex(io, env).await?,
            Self::DiffieHellmanGroup14Sha1(item) => item.kex(io, env).await?,
            Self::DiffieHellmanGroupExchangeSha256(item) => item.kex(io, env).await?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    trait AssertSendSync: Send + Sync + 'static {}
    impl AssertSendSync for Kex {}
    impl AssertSendSync for KexError {}

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<Kex>();
        assert::<KexError>();
    }

    #[tokio::test]
    async fn test_kex_send() {
        fn assert<T: Send>(t: T) -> T {
            t
        }

        let io = tokio::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")
            .await
            .unwrap();
        let io = tokio::io::BufStream::new(io);
        let mut io = crate::stream::msg::MsgStream::new(io);

        let hostkey = crate::hostkey::HostKey::gen("ssh-rsa").unwrap();

        let c_kexinit = crate::preference::PreferenceBuilder::default()
            .build()
            .unwrap()
            .to_kexinit(0);
        let s_kexinit = crate::preference::PreferenceBuilder::default()
            .build()
            .unwrap()
            .to_kexinit(0);

        let kex = assert(Kex::new("curve25519-sha256")).unwrap();
        let _ = assert(kex.kex(&mut io, "", "", &c_kexinit, &s_kexinit, &hostkey));
    }
}

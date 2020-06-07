use std::str::FromStr;

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::hash::Hasher;
use crate::hostkey::HostKey;
use crate::msg::kexinit::Kexinit;
use crate::msg::Msg;
use crate::negotiate::{AlgorithmName, UnknownNameError};
use crate::pack::Pack;
use crate::stream::msg::MsgStream;
use crate::SshError;

mod curve25519;
mod diffie_hellman;

/// SSH key exchange algorithms.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// `curve25519-sha256`
    Curve25519Sha256,

    /// `diffie-hellman-group14-sha1`
    DiffieHellmanGroup14Sha1,

    /// `diffie-hellman-group-exchange-sha256`
    DiffieHellmanGroupExchangeSha256,
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        match self {
            Self::Curve25519Sha256 => "curve25519-sha256",
            Self::DiffieHellmanGroup14Sha1 => "diffie-hellman-group14-sha1",
            Self::DiffieHellmanGroupExchangeSha256 => "diffie-hellman-group-exchange-sha256",
        }
    }
}

impl FromStr for Algorithm {
    type Err = UnknownNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "curve25519-sha256" => Ok(Self::Curve25519Sha256),
            "diffie-hellman-group14-sha1" => Ok(Self::DiffieHellmanGroup14Sha1),
            "diffie-hellman-group-exchange-sha256" => Ok(Self::DiffieHellmanGroupExchangeSha256),
            x => Err(UnknownNameError(x.into())),
        }
    }
}

impl AlgorithmName for Algorithm {
    fn defaults() -> Vec<Self> {
        vec![
            Self::Curve25519Sha256,
            Self::DiffieHellmanGroup14Sha1,
            Self::DiffieHellmanGroupExchangeSha256,
        ]
    }
}

#[derive(Debug)]
struct Env<'a> {
    c_version: &'a str,
    s_version: &'a str,
    c_kexinit: &'a Bytes,
    s_kexinit: &'a Bytes,
    hostkey: &'a HostKey,
}

#[async_trait]
trait KexTrait: Sized + Into<Kex> {
    const NAME: Algorithm;

    fn new() -> Self;

    fn hasher() -> Hasher;

    async fn kex<IO>(
        &self,
        io: &mut MsgStream<IO>,
        env: Env<'_>,
    ) -> Result<(Bytes, Bytes), SshError>
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
    pub(crate) fn hasher(&self) -> Hasher {
        match self {
            Self::Curve25519Sha256(..) => curve25519::Curve25519Sha256::hasher(),
            Self::DiffieHellmanGroup14Sha1(..) => {
                diffie_hellman::DiffieHellmanGroup14Sha1::hasher()
            }
            Self::DiffieHellmanGroupExchangeSha256(..) => {
                diffie_hellman::DiffieHellmanGroupExchangeSha256::hasher()
            }
        }
    }

    pub(crate) fn new(name: &Algorithm) -> Self {
        match name {
            Algorithm::Curve25519Sha256 => curve25519::Curve25519Sha256::new().into(),
            Algorithm::DiffieHellmanGroup14Sha1 => {
                diffie_hellman::DiffieHellmanGroup14Sha1::new().into()
            }
            Algorithm::DiffieHellmanGroupExchangeSha256 => {
                diffie_hellman::DiffieHellmanGroupExchangeSha256::new().into()
            }
        }
    }

    pub(crate) async fn kex<IO>(
        &self,
        io: &mut MsgStream<IO>,
        c_version: &str,
        s_version: &str,
        c_kexinit: &Kexinit,
        s_kexinit: &Kexinit,
        hostkey: &HostKey,
    ) -> Result<(Bytes, Bytes), SshError>
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

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<Kex>();
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

        let hostkey = crate::hostkey::HostKey::gen(&crate::hostkey::Algorithm::SshRsa).unwrap();

        let c_kexinit = crate::preference::PreferenceBuilder::default()
            .build()
            .unwrap()
            .to_kexinit();
        let s_kexinit = crate::preference::PreferenceBuilder::default()
            .build()
            .unwrap()
            .to_kexinit();

        let kex = assert(Kex::new(&Algorithm::Curve25519Sha256));
        let _ = assert(kex.kex(&mut io, "", "", &c_kexinit, &s_kexinit, &hostkey));
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

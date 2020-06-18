use std::str::FromStr;

use bytes::{Buf, Bytes, BytesMut};
use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::hash::Hasher;
use crate::key::Key;
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

    /// `diffie-hellman-group1-sha1`
    DiffieHellmanGroup1Sha1,

    /// `diffie-hellman-group14-sha1`
    DiffieHellmanGroup14Sha1,

    /// `diffie-hellman-group14-sha256`
    DiffieHellmanGroup14Sha256,

    /// `diffie-hellman-group16-sha512`
    DiffieHellmanGroup16Sha512,

    /// `diffie-hellman-group18-sha512`
    DiffieHellmanGroup18Sha512,

    /// `diffie-hellman-group-exchange-sha1`
    DiffieHellmanGroupExchangeSha1,

    /// `diffie-hellman-group-exchange-sha256`
    DiffieHellmanGroupExchangeSha256,
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        match self {
            Self::Curve25519Sha256 => "curve25519-sha256",
            Self::DiffieHellmanGroup1Sha1 => "diffie-hellman-group1-sha1",
            Self::DiffieHellmanGroup14Sha1 => "diffie-hellman-group14-sha1",
            Self::DiffieHellmanGroup14Sha256 => "diffie-hellman-group14-sha256",
            Self::DiffieHellmanGroup16Sha512 => "diffie-hellman-group16-sha512",
            Self::DiffieHellmanGroup18Sha512 => "diffie-hellman-group18-sha512",
            Self::DiffieHellmanGroupExchangeSha1 => "diffie-hellman-group-exchange-sha1",
            Self::DiffieHellmanGroupExchangeSha256 => "diffie-hellman-group-exchange-sha256",
        }
    }
}

impl FromStr for Algorithm {
    type Err = UnknownNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "curve25519-sha256" => Ok(Self::Curve25519Sha256),
            "diffie-hellman-group1-sha1" => Ok(Self::DiffieHellmanGroup1Sha1),
            "diffie-hellman-group14-sha1" => Ok(Self::DiffieHellmanGroup14Sha1),
            "diffie-hellman-group14-sha256" => Ok(Self::DiffieHellmanGroup14Sha256),
            "diffie-hellman-group16-sha512" => Ok(Self::DiffieHellmanGroup16Sha512),
            "diffie-hellman-group18-sha512" => Ok(Self::DiffieHellmanGroup18Sha512),
            "diffie-hellman-group-exchange-sha1" => Ok(Self::DiffieHellmanGroupExchangeSha1),
            "diffie-hellman-group-exchange-sha256" => Ok(Self::DiffieHellmanGroupExchangeSha256),
            x => Err(UnknownNameError(x.into())),
        }
    }
}

impl AlgorithmName for Algorithm {
    fn defaults() -> Vec<Self> {
        vec![
            Self::Curve25519Sha256,
            //Self::DiffieHellmanGroup1Sha1,
            Self::DiffieHellmanGroup14Sha1,
            Self::DiffieHellmanGroup14Sha256,
            Self::DiffieHellmanGroup16Sha512,
            Self::DiffieHellmanGroup18Sha512,
            Self::DiffieHellmanGroupExchangeSha1,
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
    hostkey: &'a Key,
}

trait KexTrait: Sized {
    fn new() -> Self;

    fn hasher() -> Hasher;

    fn kex<'a, IO>(
        &self,
        io: &'a mut MsgStream<IO>,
        env: Env<'a>,
    ) -> BoxFuture<'a, Result<(Bytes, Bytes), SshError>>
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
    DiffieHellmanGroup1Sha1(diffie_hellman::DiffieHellmanGroup1Sha1),
    DiffieHellmanGroup14Sha1(diffie_hellman::DiffieHellmanGroup14Sha1),
    DiffieHellmanGroup14Sha256(diffie_hellman::DiffieHellmanGroup14Sha256),
    DiffieHellmanGroup16Sha512(diffie_hellman::DiffieHellmanGroup16Sha512),
    DiffieHellmanGroup18Sha512(diffie_hellman::DiffieHellmanGroup18Sha512),
    DiffieHellmanGroupExchangeSha1(diffie_hellman::DiffieHellmanGroupExchangeSha1),
    DiffieHellmanGroupExchangeSha256(diffie_hellman::DiffieHellmanGroupExchangeSha256),
}

impl Kex {
    pub(crate) fn hasher(&self) -> Hasher {
        match self {
            Self::Curve25519Sha256(..) => curve25519::Curve25519Sha256::hasher(),
            Self::DiffieHellmanGroup1Sha1(..) => diffie_hellman::DiffieHellmanGroup1Sha1::hasher(),
            Self::DiffieHellmanGroup14Sha1(..) => {
                diffie_hellman::DiffieHellmanGroup14Sha1::hasher()
            }
            Self::DiffieHellmanGroup14Sha256(..) => {
                diffie_hellman::DiffieHellmanGroup14Sha256::hasher()
            }
            Self::DiffieHellmanGroup16Sha512(..) => {
                diffie_hellman::DiffieHellmanGroup16Sha512::hasher()
            }
            Self::DiffieHellmanGroup18Sha512(..) => {
                diffie_hellman::DiffieHellmanGroup18Sha512::hasher()
            }
            Self::DiffieHellmanGroupExchangeSha1(..) => {
                diffie_hellman::DiffieHellmanGroupExchangeSha1::hasher()
            }
            Self::DiffieHellmanGroupExchangeSha256(..) => {
                diffie_hellman::DiffieHellmanGroupExchangeSha256::hasher()
            }
        }
    }

    pub(crate) fn new(name: &Algorithm) -> Self {
        match name {
            Algorithm::Curve25519Sha256 => Self::Curve25519Sha256(KexTrait::new()),
            Algorithm::DiffieHellmanGroup1Sha1 => Self::DiffieHellmanGroup1Sha1(KexTrait::new()),
            Algorithm::DiffieHellmanGroup14Sha1 => Self::DiffieHellmanGroup14Sha1(KexTrait::new()),
            Algorithm::DiffieHellmanGroup14Sha256 => {
                Self::DiffieHellmanGroup14Sha256(KexTrait::new())
            }
            Algorithm::DiffieHellmanGroup16Sha512 => {
                Self::DiffieHellmanGroup16Sha512(KexTrait::new())
            }
            Algorithm::DiffieHellmanGroup18Sha512 => {
                Self::DiffieHellmanGroup18Sha512(KexTrait::new())
            }
            Algorithm::DiffieHellmanGroupExchangeSha1 => {
                Self::DiffieHellmanGroupExchangeSha1(KexTrait::new())
            }
            Algorithm::DiffieHellmanGroupExchangeSha256 => {
                Self::DiffieHellmanGroupExchangeSha256(KexTrait::new())
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
        hostkey: &Key,
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
            Self::DiffieHellmanGroup1Sha1(item) => item.kex(io, env).await?,
            Self::DiffieHellmanGroup14Sha1(item) => item.kex(io, env).await?,
            Self::DiffieHellmanGroup14Sha256(item) => item.kex(io, env).await?,
            Self::DiffieHellmanGroup16Sha512(item) => item.kex(io, env).await?,
            Self::DiffieHellmanGroup18Sha512(item) => item.kex(io, env).await?,
            Self::DiffieHellmanGroupExchangeSha1(item) => item.kex(io, env).await?,
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

        let hostkey = Key::gen(&crate::key::Algorithm::SshRsa).unwrap();

        let c_kexinit = crate::preference::PreferenceBuilder::default()
            .build()
            .await
            .unwrap()
            .to_kexinit();
        let s_kexinit = crate::preference::PreferenceBuilder::default()
            .build()
            .await
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

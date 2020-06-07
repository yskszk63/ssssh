use futures::sink::SinkExt as _;
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use tokio::stream::StreamExt as _;

use crate::msg::kex_dh_gex_group::KexDhGexGroup;
use crate::msg::kex_dh_gex_reply::KexDhGexReply;
use crate::msg::kex_ecdh_reply::KexEcdhReply;
use crate::msg::GexMsg;
use crate::pack::{Mpint, Pack};

use super::*;

#[derive(Debug)]
pub(crate) struct DiffieHellmanGroup14Sha1 {}

#[async_trait]
impl KexTrait for DiffieHellmanGroup14Sha1 {
    const NAME: Algorithm = Algorithm::DiffieHellmanGroup14Sha1;

    fn new() -> Self {
        Self {}
    }

    fn hasher() -> Hasher {
        Hasher::sha1()
    }

    #[allow(clippy::many_single_char_names)]
    async fn kex<IO>(
        &self,
        io: &mut MsgStream<IO>,
        env: Env<'_>,
    ) -> Result<(Bytes, Bytes), SshError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut hasher = Self::hasher();
        env.c_version.pack(&mut hasher);
        env.s_version.pack(&mut hasher);
        env.c_kexinit.pack(&mut hasher);
        env.s_kexinit.pack(&mut hasher);
        env.hostkey.publickey().pack(&mut hasher);

        // FIXME use kexdh_init
        let kexdh_init = match io.next().await {
            Some(Ok(Msg::KexEcdhInit(msg))) => msg,
            Some(Ok(msg)) => return Err(SshError::KexUnexpectedMsg(format!("{:?}", msg))),
            Some(Err(e)) => return Err(e),
            None => return Err(SshError::KexUnexpectedEof),
        };

        let e = kexdh_init.ephemeral_public_key();
        e.pack(&mut hasher);
        let e = BigNum::from_slice(e).map_err(SshError::kex_error)?;

        let p = get_p(14)?;
        let y = gen_y()?;
        let g = get_g()?;

        let mut ctx = BigNumContext::new().map_err(SshError::kex_error)?;
        let mut f = BigNum::new().map_err(SshError::kex_error)?;
        f.mod_exp(&g, &y, &p, &mut ctx)
            .map_err(SshError::kex_error)?;
        let mut f = f.to_vec();
        if f[0] & 0x80 != 0 {
            f.insert(0, 0);
        }
        let f = Bytes::from(f);
        f.clone().pack(&mut hasher);

        let mut ctx = BigNumContext::new().map_err(SshError::kex_error)?;
        let mut k = BigNum::new().map_err(SshError::kex_error)?;
        k.mod_exp(&e, &y, &p, &mut ctx)
            .map_err(SshError::kex_error)?;
        let k = Bytes::from(k.to_vec());
        Mpint::new(k.clone()).pack(&mut hasher);

        let h = hasher.finish();

        let signature = env.hostkey.sign(&h);

        let reply = KexEcdhReply::new(env.hostkey.publickey(), f, signature);

        io.send(reply.into()).await?;

        Ok((h, k))
    }
}

fn get_p(n: u32) -> Result<BigNum, SshError> {
    match n {
        1 => BigNum::get_rfc2409_prime_768(),
        2 => BigNum::get_rfc2409_prime_1024(),
        5 => BigNum::get_rfc3526_prime_1536(),
        14 => BigNum::get_rfc3526_prime_2048(),
        15 => BigNum::get_rfc3526_prime_3072(),
        16 => BigNum::get_rfc3526_prime_4096(),
        17 => BigNum::get_rfc3526_prime_6144(),
        18 => BigNum::get_rfc3526_prime_8192(),
        x => panic!("out of range {}", x),
    }
    .map_err(SshError::kex_error)
}

fn get_g() -> Result<BigNum, SshError> {
    BigNum::from_u32(2).map_err(SshError::kex_error)
}

fn gen_y() -> Result<BigNum, SshError> {
    let mut y = BigNum::new().map_err(SshError::kex_error)?;
    y.rand(160, MsbOption::MAYBE_ZERO, false)
        .map_err(SshError::kex_error)?;
    Ok(y)
}

impl From<DiffieHellmanGroup14Sha1> for Kex {
    fn from(v: DiffieHellmanGroup14Sha1) -> Self {
        Self::DiffieHellmanGroup14Sha1(v)
    }
}

#[derive(Debug)]
pub(crate) struct DiffieHellmanGroupExchangeSha256 {}

#[async_trait]
impl KexTrait for DiffieHellmanGroupExchangeSha256 {
    const NAME: Algorithm = Algorithm::DiffieHellmanGroupExchangeSha256;

    fn new() -> Self {
        Self {}
    }

    fn hasher() -> Hasher {
        Hasher::sha256()
    }

    #[allow(clippy::many_single_char_names)]
    async fn kex<IO>(
        &self,
        io: &mut MsgStream<IO>,
        env: Env<'_>,
    ) -> Result<(Bytes, Bytes), SshError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut io = io.context::<GexMsg>();
        let mut hasher = Self::hasher();

        env.c_version.pack(&mut hasher);
        env.s_version.pack(&mut hasher);
        env.c_kexinit.pack(&mut hasher);
        env.s_kexinit.pack(&mut hasher);
        env.hostkey.publickey().pack(&mut hasher);

        let range = match io.next().await {
            Some(Ok(GexMsg::KexDhGexRequestOld(msg))) => {
                msg.n().pack(&mut hasher);
                *msg.n()..=*msg.n()
            }
            Some(Ok(GexMsg::KexDhGexRequest(msg))) => {
                msg.min().pack(&mut hasher);
                msg.n().pack(&mut hasher);
                msg.max().pack(&mut hasher);
                *msg.min()..=*msg.max()
            }
            Some(Ok(msg)) => return Err(SshError::KexUnexpectedMsg(format!("{:?}", msg))),
            Some(Err(e)) => return Err(e),
            None => return Err(SshError::KexUnexpectedEof),
        };

        let p = if range.contains(&8192) {
            get_p(18)
        } else if range.contains(&6144) {
            get_p(17)
        } else if range.contains(&4096) {
            get_p(16)
        } else if range.contains(&3072) {
            get_p(15)
        } else if range.contains(&2048) {
            get_p(14)
        } else if range.contains(&1536) {
            get_p(5)
        } else if range.contains(&1024) {
            get_p(2)
        } else if range.contains(&768) {
            get_p(1)
        } else {
            todo!()
        }?;
        Mpint::new(p.to_vec()).pack(&mut hasher);

        let g = get_g()?;
        Mpint::new(g.to_vec()).pack(&mut hasher);

        let group = KexDhGexGroup::new(Mpint::new(p.to_vec()), Mpint::new(g.to_vec()));
        io.send(group.into()).await?;

        let kex_dh_gex_init = match io.next().await {
            Some(Ok(GexMsg::KexDhGexInit(msg))) => msg,
            Some(Ok(msg)) => return Err(SshError::KexUnexpectedMsg(format!("{:?}", msg))),
            Some(Err(e)) => return Err(e),
            None => return Err(SshError::KexUnexpectedEof),
        };

        let e = kex_dh_gex_init.e();
        e.pack(&mut hasher);
        let e = BigNum::from_slice(e.as_ref()).map_err(SshError::kex_error)?;

        let y = gen_y()?;

        let mut ctx = BigNumContext::new().map_err(SshError::kex_error)?;
        let mut f = BigNum::new().map_err(SshError::kex_error)?;
        f.mod_exp(&g, &y, &p, &mut ctx)
            .map_err(SshError::kex_error)?;
        let mut f = f.to_vec();
        if f[0] & 0x80 != 0 {
            f.insert(0, 0);
        }
        Mpint::new(f.clone()).pack(&mut hasher);

        let mut ctx = BigNumContext::new().map_err(SshError::kex_error)?;
        let mut k = BigNum::new().map_err(SshError::kex_error)?;
        k.mod_exp(&e, &y, &p, &mut ctx)
            .map_err(SshError::kex_error)?;
        let mut k = k.to_vec();
        if k[0] & 0x80 != 0 {
            k.insert(0, 0);
        }
        Mpint::new(k.clone()).pack(&mut hasher);

        let h = hasher.finish();

        let signature = env.hostkey.sign(&h);

        let reply = KexDhGexReply::new(env.hostkey.publickey(), f.into(), signature);
        io.send(reply.into()).await?;

        Ok((h, k.into()))
    }
}

impl From<DiffieHellmanGroupExchangeSha256> for Kex {
    fn from(v: DiffieHellmanGroupExchangeSha256) -> Self {
        Self::DiffieHellmanGroupExchangeSha256(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let kex = assert(DiffieHellmanGroup14Sha1::new());
        let env = Env {
            c_version: "",
            s_version: "",
            c_kexinit: &to_msg_bytes(&c_kexinit),
            s_kexinit: &to_msg_bytes(&s_kexinit),
            hostkey: &hostkey,
        };
        assert(kex.kex(&mut io, env));
    }
}

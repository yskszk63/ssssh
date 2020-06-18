use std::marker::PhantomData;

use futures::future::FutureExt as _;
use futures::sink::SinkExt as _;
use openssl::bn::{BigNum, BigNumContext, BigNumContextRef, BigNumRef, MsbOption};
use openssl::error::ErrorStack;
use tokio::stream::StreamExt as _;

use crate::msg::kex_dh_gex_group::KexDhGexGroup;
use crate::msg::kex_dh_gex_reply::KexDhGexReply;
use crate::msg::kex_ecdh_reply::KexEcdhReply;
use crate::msg::GexMsg;
use crate::pack::{Mpint, Pack};

use super::*;

pub(crate) type DiffieHellmanGroup1Sha1 = DiffieHellman<Group1, Sha1>;
pub(crate) type DiffieHellmanGroup14Sha1 = DiffieHellman<Group14, Sha1>;
pub(crate) type DiffieHellmanGroup14Sha256 = DiffieHellman<Group14, Sha256>;
pub(crate) type DiffieHellmanGroup16Sha512 = DiffieHellman<Group16, Sha512>;
pub(crate) type DiffieHellmanGroup18Sha512 = DiffieHellman<Group18, Sha512>;
pub(crate) type DiffieHellmanGroupExchangeSha1 = DiffieHellmanGroupExchange<Sha1>;
pub(crate) type DiffieHellmanGroupExchangeSha256 = DiffieHellmanGroupExchange<Sha256>;

pub(crate) trait Group {
    const P: fn() -> Result<BigNum, ErrorStack>;
}

pub(crate) trait Sha {
    const HASHER: fn() -> Hasher;
}

#[derive(Debug)]
pub(crate) enum Group1 {}

impl Group for Group1 {
    const P: fn() -> Result<BigNum, ErrorStack> = BigNum::get_rfc2409_prime_1024;
}

#[derive(Debug)]
pub(crate) enum Group14 {}

impl Group for Group14 {
    const P: fn() -> Result<BigNum, ErrorStack> = BigNum::get_rfc3526_prime_2048;
}

#[derive(Debug)]
pub(crate) enum Group16 {}

impl Group for Group16 {
    const P: fn() -> Result<BigNum, ErrorStack> = BigNum::get_rfc3526_prime_4096;
}

#[derive(Debug)]
pub(crate) enum Group18 {}

impl Group for Group18 {
    const P: fn() -> Result<BigNum, ErrorStack> = BigNum::get_rfc3526_prime_8192;
}

#[derive(Debug)]
pub(crate) enum Sha1 {}

impl Sha for Sha1 {
    const HASHER: fn() -> Hasher = Hasher::sha1;
}

#[derive(Debug)]
pub(crate) enum Sha256 {}

impl Sha for Sha256 {
    const HASHER: fn() -> Hasher = Hasher::sha256;
}

#[derive(Debug)]
pub(crate) enum Sha512 {}

impl Sha for Sha512 {
    const HASHER: fn() -> Hasher = Hasher::sha512;
}

#[derive(Debug)]
pub(crate) struct DiffieHellman<G, H> {
    _phantom: PhantomData<(G, H)>,
}

impl<G, H> KexTrait for DiffieHellman<G, H>
where
    G: Group,
    H: Sha,
{
    fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    fn hasher() -> Hasher {
        H::HASHER()
    }

    #[allow(clippy::many_single_char_names)]
    fn kex<'a, IO>(
        &self,
        io: &'a mut MsgStream<IO>,
        env: Env<'a>,
    ) -> BoxFuture<'a, Result<(Bytes, Bytes), SshError>>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        async move {
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

            let p = (G::P()).map_err(SshError::kex_error)?;
            let y = gen_y()?;
            let g = get_g()?;

            let mut ctx = BigNumContext::new().map_err(SshError::kex_error)?;

            let f = mod_exp(&g, &y, &p, &mut ctx)?;
            f.pack(&mut hasher);

            let k = mod_exp(&e, &y, &p, &mut ctx)?;
            k.pack(&mut hasher);

            let h = hasher.finish();

            let signature = env.hostkey.sign(&h);

            let reply = KexEcdhReply::new(env.hostkey.publickey(), f, signature);

            io.send(reply.into()).await?;

            Ok((h, k))
        }
        .boxed()
    }
}

fn mod_exp(
    a: &BigNumRef,
    p: &BigNumRef,
    m: &BigNumRef,
    cx: &mut BigNumContextRef,
) -> Result<Bytes, SshError> {
    let mut r = BigNum::new().map_err(SshError::kex_error)?;
    r.mod_exp(a, p, m, cx).map_err(SshError::kex_error)?;
    let r = Mpint::new(r.to_vec()).as_ref().to_bytes();
    Ok(r)
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

#[derive(Debug)]
pub(crate) struct DiffieHellmanGroupExchange<H> {
    _phantom: PhantomData<H>,
}

impl<H> KexTrait for DiffieHellmanGroupExchange<H>
where
    H: Sha,
{
    fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    fn hasher() -> Hasher {
        H::HASHER()
    }

    #[allow(clippy::many_single_char_names)]
    fn kex<'a, IO>(
        &self,
        io: &'a mut MsgStream<IO>,
        env: Env<'a>,
    ) -> BoxFuture<'a, Result<(Bytes, Bytes), SshError>>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        async move {
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
                BigNum::get_rfc3526_prime_8192()
            } else if range.contains(&6144) {
                BigNum::get_rfc3526_prime_6144()
            } else if range.contains(&4096) {
                BigNum::get_rfc3526_prime_4096()
            } else if range.contains(&3072) {
                BigNum::get_rfc3526_prime_3072()
            } else if range.contains(&2048) {
                BigNum::get_rfc3526_prime_2048()
            } else if range.contains(&1536) {
                BigNum::get_rfc3526_prime_1536()
            } else if range.contains(&1024) {
                BigNum::get_rfc2409_prime_1024()
            } else if range.contains(&768) {
                BigNum::get_rfc2409_prime_768()
            } else {
                todo!()
            }
            .map_err(SshError::kex_error)?;
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

            let f = mod_exp(&g, &y, &p, &mut ctx)?;
            f.pack(&mut hasher);

            let k = mod_exp(&e, &y, &p, &mut ctx)?;
            k.pack(&mut hasher);

            let h = hasher.finish();

            let signature = env.hostkey.sign(&h);

            let reply = KexDhGexReply::new(env.hostkey.publickey(), f, signature);
            io.send(reply.into()).await?;

            Ok((h, k))
        }
        .boxed()
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

        let hostkey = crate::key::Key::gen(&crate::key::Algorithm::SshRsa).unwrap();

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

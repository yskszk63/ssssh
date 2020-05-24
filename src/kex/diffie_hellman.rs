use futures::sink::SinkExt as _;
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256};
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
    const NAME: &'static str = "diffie-hellman-group14-sha1";

    fn new() -> Self {
        Self {}
    }

    fn hash<B: Buf>(buf: &B) -> Bytes {
        let hash = digest(&SHA1, buf.bytes());
        hash.as_ref().to_bytes()
    }

    #[allow(clippy::many_single_char_names)]
    async fn kex<IO>(
        &self,
        io: &mut MsgStream<IO>,
        env: Env<'_>,
    ) -> Result<(Bytes, Bytes), KexError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        // FIXME use kexdh_init
        let kexdh_init = match io.next().await {
            Some(Ok(Msg::KexEcdhInit(msg))) => msg,
            Some(Ok(msg)) => return Err(KexError::UnexpectedMsg(format!("{:?}", msg))),
            Some(Err(e)) => return Err(e.into()),
            None => return Err(KexError::UnexpectedEof),
        };

        let e = kexdh_init.ephemeral_public_key();
        let e = BigNum::from_slice(e).unwrap();

        let p = get_p(14);
        let y = gen_y();
        let g = get_g();

        let mut ctx = BigNumContext::new().unwrap();
        let mut f = BigNum::new().unwrap();
        f.mod_exp(&g, &y, &p, &mut ctx).unwrap();
        let mut f = f.to_vec();
        if f[0] & 0x80 != 0 {
            f.insert(0, 0);
        }

        let mut ctx = BigNumContext::new().unwrap();
        let mut k = BigNum::new().unwrap();
        k.mod_exp(&e, &y, &p, &mut ctx).unwrap();
        let k = k.to_vec();

        let h = compute_hash(&env, kexdh_init.ephemeral_public_key(), &f, &k);

        let signature = env.hostkey.sign(&h);

        let reply = KexEcdhReply::new(env.hostkey.publickey(), f.into(), signature);

        io.send(reply.into()).await?;

        Ok((h, k.into()))
    }
}

fn get_p(n: u32) -> BigNum {
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
    .unwrap()
}

fn get_g() -> BigNum {
    BigNum::from_u32(2).unwrap()
}

fn gen_y() -> BigNum {
    let mut y = BigNum::new().unwrap();
    y.rand(160, MsbOption::MAYBE_ZERO, false).unwrap();
    y
}

fn compute_hash(env: &Env<'_>, mut e: &[u8], mut f: &[u8], mut k: &[u8]) -> Bytes {
    let mut buf = BytesMut::new();
    env.c_version.pack(&mut buf);
    env.s_version.pack(&mut buf);
    env.c_kexinit.pack(&mut buf);
    env.s_kexinit.pack(&mut buf);
    env.hostkey.publickey().pack(&mut buf);
    e.to_bytes().pack(&mut buf);
    f.to_bytes().pack(&mut buf);
    Mpint::new(k.to_bytes()).pack(&mut buf);

    DiffieHellmanGroup14Sha1::hash(&buf)
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
    const NAME: &'static str = "diffie-hellman-group-exchange-sha256";

    fn new() -> Self {
        Self {}
    }

    fn hash<B: Buf>(buf: &B) -> Bytes {
        let hash = digest(&SHA256, buf.bytes());
        hash.as_ref().to_bytes()
    }

    #[allow(clippy::many_single_char_names)]
    async fn kex<IO>(
        &self,
        io: &mut MsgStream<IO>,
        env: Env<'_>,
    ) -> Result<(Bytes, Bytes), KexError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let mut io = io.context::<GexMsg>();

        let (min, n, max) = match io.next().await {
            Some(Ok(GexMsg::KexDhGexRequestOld(msg))) => {
                (None, *msg.n(), None)
            }
            Some(Ok(GexMsg::KexDhGexRequest(msg))) => {
                (Some(*msg.min()), *msg.n(), Some(*msg.max()))
            }
            Some(Ok(msg)) => return Err(KexError::UnexpectedMsg(format!("{:?}", msg))),
            Some(Err(e)) => return Err(e.into()),
            None => return Err(KexError::UnexpectedEof),
        };

        let range = min.unwrap_or(n)..=max.unwrap_or(n);
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
        };

        let g = get_g();

        let group = KexDhGexGroup::new(Mpint::new(p.to_vec()), Mpint::new(g.to_vec()));
        io.send(group.into()).await?;

        let kex_dh_gex_init = match io.next().await {
            Some(Ok(GexMsg::KexDhGexInit(msg))) => msg,
            Some(Ok(msg)) => return Err(KexError::UnexpectedMsg(format!("{:?}", msg))),
            Some(Err(e)) => return Err(e.into()),
            None => return Err(KexError::UnexpectedEof),
        };

        let e = kex_dh_gex_init.e();
        let e = BigNum::from_slice(e.as_ref()).unwrap();

        let y = gen_y();

        let mut ctx = BigNumContext::new().unwrap();
        let mut f = BigNum::new().unwrap();
        f.mod_exp(&g, &y, &p, &mut ctx).unwrap();
        let mut f = f.to_vec();
        if f[0] & 0x80 != 0 {
            f.insert(0, 0);
        }

        let mut ctx = BigNumContext::new().unwrap();
        let mut k = BigNum::new().unwrap();
        k.mod_exp(&e, &y, &p, &mut ctx).unwrap();
        let mut k = k.to_vec();
        if k[0] & 0x80 != 0 {
            k.insert(0, 0);
        }

        let h = compute_gax_hash(
            &env,
            min,
            n,
            max,
            &Mpint::new(p.to_vec()),
            &Mpint::new(g.to_vec()),
            &Mpint::new(e.to_vec()),
            &Mpint::new(f.to_vec()),
            &Mpint::new(k.to_vec()),
        );

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

fn compute_gax_hash(
    env: &Env<'_>,
    min: Option<u32>,
    n: u32,
    max: Option<u32>,
    p: &Mpint,
    g: &Mpint,
    e: &Mpint,
    f: &Mpint,
    k: &Mpint,
) -> Bytes {
    let mut buf = BytesMut::new();
    env.c_version.pack(&mut buf);
    env.s_version.pack(&mut buf);
    env.c_kexinit.pack(&mut buf);
    env.s_kexinit.pack(&mut buf);
    env.hostkey.publickey().pack(&mut buf);
    if let Some(min) = min {
        min.pack(&mut buf);
    }
    n.pack(&mut buf);
    if let Some(max) = max {
        max.pack(&mut buf);
    }
    p.pack(&mut buf);
    g.pack(&mut buf);
    e.pack(&mut buf);
    f.pack(&mut buf);
    k.pack(&mut buf);

    DiffieHellmanGroupExchangeSha256::hash(&buf)
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

        let hostkey = crate::hostkey::HostKey::gen("ssh-rsa").unwrap();

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

use futures::sink::SinkExt as _;
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use ring::digest::{digest, SHA1_FOR_LEGACY_USE_ONLY as SHA1};
use tokio::stream::StreamExt as _;

use crate::msg::kex_ecdh_reply::KexEcdhReply;
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

        let p = get_p();
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

fn get_p() -> BigNum {
    BigNum::get_rfc3526_prime_2048().unwrap()
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

        let c_kexinit = crate::preference::Preference::default().to_kexinit(0);
        let s_kexinit = crate::preference::Preference::default().to_kexinit(0);

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

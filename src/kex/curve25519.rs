use futures::sink::SinkExt as _;
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519};
use ring::digest::{digest, SHA256};
use ring::error::Unspecified;
use ring::rand::SystemRandom;
use tokio::stream::StreamExt as _;

use crate::msg::kex_ecdh_reply::KexEcdhReply;
use crate::pack::{Mpint, Pack};

use super::*;

#[derive(Debug)]
pub(crate) struct Curve25519Sha256 {}

#[async_trait]
impl KexTrait for Curve25519Sha256 {
    const NAME: &'static str = "curve25519-sha256";

    fn new() -> Self {
        Self {}
    }

    fn hash<B: Buf>(buf: &B) -> Bytes {
        let hash = digest(&SHA256, buf.bytes());
        hash.as_ref().to_bytes()
    }

    async fn kex<IO>(
        &self,
        io: &mut MsgStream<IO>,
        env: Env<'_>,
    ) -> Result<(Bytes, Bytes), KexError>
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send,
    {
        let kex_ecdh_init = match io.next().await {
            Some(Ok(Msg::KexEcdhInit(msg))) => msg,
            Some(Ok(msg)) => return Err(KexError::UnexpectedMsg(format!("{:?}", msg))),
            Some(Err(e)) => return Err(e.into()),
            None => return Err(KexError::UnexpectedEof),
        };

        let client_ephemeral_public_key = kex_ecdh_init.ephemeral_public_key();
        let client_ephemeral_public_key =
            UnparsedPublicKey::new(&X25519, client_ephemeral_public_key);

        let (server_ephemeral_private_key, server_ephemeral_public_key) = gen_keypair()?;
        let key = agree_ephemeral(
            server_ephemeral_private_key,
            &client_ephemeral_public_key,
            Unspecified,
            |mut e| Ok(e.to_bytes()),
        )
        .map_err(|e| KexError::Any(e.to_string()))?;

        let hash = compute_hash(
            &env,
            client_ephemeral_public_key.bytes(),
            server_ephemeral_public_key.as_ref(),
            &key,
        );

        let signature = env.hostkey.sign(&hash);

        let kex_ecdh_reply = KexEcdhReply::new(
            env.hostkey.publickey(),
            server_ephemeral_public_key.as_ref().to_bytes(),
            signature,
        );

        io.send(kex_ecdh_reply.into()).await?;

        Ok((hash, key))
    }
}

fn gen_keypair() -> Result<(EphemeralPrivateKey, PublicKey), KexError> {
    let rand = SystemRandom::new();
    let private =
        EphemeralPrivateKey::generate(&X25519, &rand).map_err(|e| KexError::Any(e.to_string()))?;
    let public = private
        .compute_public_key()
        .map_err(|e| KexError::Any(e.to_string()))?;
    Ok((private, public))
}

fn compute_hash(
    env: &Env<'_>,
    mut c_ephemeral: &[u8],
    mut s_ephemeral: &[u8],
    mut shared_key: &[u8],
) -> Bytes {
    let mut buf = BytesMut::new();
    env.c_version.pack(&mut buf);
    env.s_version.pack(&mut buf);
    env.c_kexinit.pack(&mut buf);
    env.s_kexinit.pack(&mut buf);
    env.hostkey.publickey().pack(&mut buf);
    c_ephemeral.to_bytes().pack(&mut buf);
    s_ephemeral.to_bytes().pack(&mut buf);
    Mpint::new(shared_key.to_bytes()).pack(&mut buf);

    Curve25519Sha256::hash(&buf)
}

impl From<Curve25519Sha256> for Kex {
    fn from(v: Curve25519Sha256) -> Self {
        Self::Curve25519Sha256(v)
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

        let c_kexinit = crate::preference::PreferenceBuilder::default()
            .build()
            .unwrap()
            .to_kexinit(0);
        let s_kexinit = crate::preference::PreferenceBuilder::default()
            .build()
            .unwrap()
            .to_kexinit(0);

        let kex = assert(Curve25519Sha256::new());
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

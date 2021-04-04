use futures::future::FutureExt as _;
use futures::sink::SinkExt as _;
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519};
use ring::error::Unspecified;
use ring::rand::SystemRandom;
use tokio_stream::StreamExt as _;

use crate::msg::kex_ecdh_reply::KexEcdhReply;
use crate::pack::{Mpint, Pack};

use super::*;

#[derive(Debug)]
pub(crate) struct Curve25519Sha256 {}

impl KexTrait for Curve25519Sha256 {
    fn new() -> Self {
        Self {}
    }

    fn hasher() -> Hasher {
        Hasher::sha256()
    }

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

            let kex_ecdh_init = match io.next().await {
                Some(Ok(Msg::KexEcdhInit(msg))) => msg,
                Some(Ok(msg)) => return Err(SshError::KexUnexpectedMsg(format!("{:?}", msg))),
                Some(Err(e)) => return Err(e),
                None => return Err(SshError::KexUnexpectedEof),
            };

            let client_ephemeral_public_key = kex_ecdh_init.ephemeral_public_key();
            let client_ephemeral_public_key =
                UnparsedPublicKey::new(&X25519, client_ephemeral_public_key);
            Bytes::from(client_ephemeral_public_key.clone().bytes().to_vec()).pack(&mut hasher);

            let (server_ephemeral_private_key, server_ephemeral_public_key) = gen_keypair()?;
            Bytes::from(server_ephemeral_public_key.as_ref().to_vec()).pack(&mut hasher);

            let key = agree_ephemeral(
                server_ephemeral_private_key,
                &client_ephemeral_public_key,
                Unspecified,
                |mut e| Ok(e.copy_to_bytes(e.remaining())),
            )
            .map_err(SshError::kex_error)?;
            Mpint::new(key.clone()).pack(&mut hasher);

            let hash = hasher.finish();

            let signature = env.hostkey.sign(&hash);

            let mut server_ephemeral_public_key = server_ephemeral_public_key.as_ref();
            let kex_ecdh_reply = KexEcdhReply::new(
                env.hostkey.publickey(),
                server_ephemeral_public_key.copy_to_bytes(server_ephemeral_public_key.remaining()),
                signature,
            );

            io.send(kex_ecdh_reply.into()).await?;

            Ok((hash, key))
        }
        .boxed()
    }
}

fn gen_keypair() -> Result<(EphemeralPrivateKey, PublicKey), SshError> {
    let rand = SystemRandom::new();
    let private = EphemeralPrivateKey::generate(&X25519, &rand).map_err(SshError::kex_error)?;
    let public = private.compute_public_key().map_err(SshError::kex_error)?;
    Ok((private, public))
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

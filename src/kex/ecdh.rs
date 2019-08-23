use bytes::Bytes;
use futures::{Sink, SinkExt as _, TryStream, TryStreamExt as _};
use ring::agreement::{agree_ephemeral, EphemeralPrivateKey, PublicKey, UnparsedPublicKey, X25519};
use ring::digest::{Context, SHA256};
use ring::error::Unspecified;
use ring::rand::SystemRandom;

use super::{KexEnv, KexError, KexResult, KexReturn};
use crate::msg::{KexEcdhReply, Message, MessageError};
use crate::sshbuf::SshBufMut as _;

#[allow(clippy::module_name_repetitions)]
pub(crate) async fn kex_ecdh<Rx, Tx>(env: &mut KexEnv<'_, Tx, Rx>) -> KexResult
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = Message, Error = MessageError> + Unpin,
{
    let kex_ecdh_init = if let Some(Message::KexEcdhInit(e)) = env.rx.try_next().await? {
        e
    } else {
        return Err(KexError::ProtocolError);
    };

    let client_ephemeral_public = kex_ecdh_init.ephemeral_public_key();
    let client_ephemeral_public = UnparsedPublicKey::new(&X25519, client_ephemeral_public);

    let (server_ephemeral_secret, server_ephemeral_public) = gen_keypair();
    let key = agree_ephemeral(
        server_ephemeral_secret,
        &client_ephemeral_public,
        Unspecified,
        |e| Ok(Bytes::from(e)),
    )
    .unwrap();

    let hash = calculate_hash(
        env,
        client_ephemeral_public.bytes(),
        server_ephemeral_public.as_ref(),
        &key,
    );
    let signature = env.hostkey.sign(&hash);

    env.tx
        .send(
            KexEcdhReply::new(
                env.hostkey.publickey(),
                server_ephemeral_public.as_ref(),
                &signature,
            )
            .into(),
        )
        .await?;

    Ok(KexReturn { hash, key })
}

fn gen_keypair() -> (EphemeralPrivateKey, PublicKey) {
    let rnd = SystemRandom::new();
    let secret = EphemeralPrivateKey::generate(&X25519, &rnd).unwrap();
    let publickey = secret.compute_public_key().unwrap();
    (secret, publickey)
}

fn calculate_hash<Tx, Rx>(
    env: &KexEnv<'_, Tx, Rx>,
    client_ephemeral_public: &[u8],
    server_ephemeral_public: &[u8],
    shared_key: &[u8],
) -> Bytes
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = Message, Error = MessageError> + Unpin,
{
    let client_version = env.version.client();
    let server_version = env.version.server();
    let client_kexinit = env.client_kexinit.to_bytes();
    let server_kexinit = env.server_kexinit.to_bytes();
    let hostkey = env.hostkey;

    let mut ctx = Context::new(&SHA256);
    ctx.put_binary_string(client_version);
    ctx.put_binary_string(server_version);
    ctx.put_binary_string(&client_kexinit);
    ctx.put_binary_string(&server_kexinit);
    hostkey.put_to(&mut ctx);
    ctx.put_binary_string(client_ephemeral_public);
    ctx.put_binary_string(server_ephemeral_public);
    ctx.put_mpint(shared_key);
    let hash = ctx.finish();
    Bytes::from(hash.as_ref())
}

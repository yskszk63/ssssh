use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt as _, TryStream, TryStreamExt as _};
use rand::{thread_rng, RngCore as _};
use sodiumoxide::crypto::scalarmult::curve25519;

use super::{KexEnv, KexError, KexResult, KexReturn};
use crate::msg::{KexEcdhReply, Message, MessageError};
use crate::sshbuf::SshBufMut as _;

#[allow(clippy::module_name_repetitions)]
pub async fn kex_ecdh<Rx, Tx>(env: &mut KexEnv<'_, Tx, Rx>) -> KexResult
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
    let client_ephemeral_public = curve25519::GroupElement::from_slice(client_ephemeral_public)
        .ok_or_else(|| KexError::ProtocolError)?;
    let (server_ephemeral_secret, server_ephemeral_public) = gen_keypair();
    let key = match curve25519::scalarmult(&server_ephemeral_secret, &client_ephemeral_public) {
        Ok(e) => Bytes::from(&e.0[..]),
        Err(..) => return Err(KexError::ProtocolError),
    };

    let hash = calculate_hash(
        env,
        &client_ephemeral_public.0,
        &server_ephemeral_public.0,
        &key,
    );
    let signature = env.hostkey.sign(&hash).unwrap();

    env.tx
        .send(
            KexEcdhReply::new(
                env.hostkey.publickey(),
                &server_ephemeral_public.0,
                &signature,
            )
            .into(),
        )
        .await?;

    Ok(KexReturn { hash, key })
}

fn gen_keypair() -> (curve25519::Scalar, curve25519::GroupElement) {
    let mut secret = [0; curve25519::SCALARBYTES];
    thread_rng().fill_bytes(&mut secret);
    let secret = curve25519::Scalar(secret);
    let publickey = curve25519::scalarmult_base(&secret);

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

    let mut buf = BytesMut::with_capacity(1024 * 8);
    buf.put_binary_string(client_version);
    buf.put_binary_string(server_version);
    buf.put_binary_string(&client_kexinit);
    buf.put_binary_string(&server_kexinit);
    hostkey.put_to(&mut buf);
    buf.put_binary_string(client_ephemeral_public);
    buf.put_binary_string(server_ephemeral_public);
    buf.put_mpint(shared_key);

    let hash = sodiumoxide::crypto::hash::sha256::hash(&buf).0;
    Bytes::from(&hash[..])
}

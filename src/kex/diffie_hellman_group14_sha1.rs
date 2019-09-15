use bytes::Bytes;
use futures::{Sink, SinkExt as _, TryStream, TryStreamExt as _};
use openssl::bn::{BigNum, BigNumContext, MsbOption};
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY as SHA1};

use super::{KexEnv, KexError, KexResult, KexReturn};
use crate::msg::{KexEcdhReply, Message, MessageError};
use crate::sshbuf::SshBufMut as _;

#[allow(clippy::module_name_repetitions)]
pub(crate) async fn kex_dh<Rx, Tx>(env: &mut KexEnv<'_, Tx, Rx>) -> KexResult
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = (u32, Message), Error = MessageError> + Unpin,
{
    let kex_dh_init = if let Some((_, Message::KexEcdhInit(e))) = env.rx.try_next().await? {
        e
    } else {
        return Err(KexError::ProtocolError);
    };

    let e = kex_dh_init.ephemeral_public_key();
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

    let h = calculate_hash(env, kex_dh_init.ephemeral_public_key(), &f, &k);

    let signature = env.hostkey.sign(&h);

    env.tx
        .send(KexEcdhReply::new(env.hostkey.publickey(), f.to_vec().as_ref(), &signature).into())
        .await?;

    Ok(KexReturn {
        hash: h,
        key: Bytes::from(k),
    })
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

fn calculate_hash<Tx, Rx>(env: &KexEnv<'_, Tx, Rx>, e: &[u8], f: &[u8], k: &[u8]) -> Bytes
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = (u32, Message), Error = MessageError> + Unpin,
{
    let client_version = env.version.client();
    let server_version = env.version.server();
    let client_kexinit = env.client_kexinit.to_bytes();
    let server_kexinit = env.server_kexinit.to_bytes();
    let hostkey = env.hostkey;

    let mut ctx = Context::new(&SHA1);
    ctx.put_binary_string(client_version);
    ctx.put_binary_string(server_version);
    ctx.put_binary_string(&client_kexinit);
    ctx.put_binary_string(&server_kexinit);
    hostkey.put_to(&mut ctx);
    ctx.put_binary_string(e);
    ctx.put_binary_string(f);
    ctx.put_mpint(k);
    let hash = ctx.finish();
    Bytes::from(hash.as_ref())
}

use std::io;
use std::sync::{Arc, Mutex};

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use failure::Fail;
use rand::{CryptoRng, RngCore};
use tokio_util::codec::{Decoder, Encoder};

use super::{Packet, State};
use crate::compression::CompressionError;
use crate::encrypt::EncryptError;

const MINIMUM_PAD_SIZE: usize = 4;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Fail)]
pub(crate) enum CodecError {
    #[fail(display = "IO Error Ocurred {}", _0)]
    Io(io::Error),
    #[fail(display = "Unable to acqurie shared state lock.")]
    UnabledToSharedStateLock,
    #[fail(display = "CompressionError")]
    CompressionError(#[fail(cause)] CompressionError),
    #[fail(display = "EncryptError")]
    EncryptError(#[fail(cause)] EncryptError),
}

impl From<io::Error> for CodecError {
    fn from(v: io::Error) -> Self {
        Self::Io(v)
    }
}

impl From<CompressionError> for CodecError {
    fn from(v: CompressionError) -> Self {
        Self::CompressionError(v)
    }
}

impl From<EncryptError> for CodecError {
    fn from(v: EncryptError) -> Self {
        Self::EncryptError(v)
    }
}

#[allow(clippy::module_name_repetitions)]
pub(crate) type CodecResult<T> = Result<T, CodecError>;

#[derive(Debug)]
enum EncryptState {
    Initial,
    FillBuffer {
        encrypted_first: Bytes,
        first: Bytes,
        len: usize,
    },
    Sign {
        encrypted: Bytes,
        plain: Bytes,
    },
}

pub(crate) struct Codec<R>
where
    R: RngCore + CryptoRng,
{
    rng: R,
    state: Arc<Mutex<State>>,
    encrypt_state: EncryptState,
}

impl<R: RngCore + CryptoRng> std::fmt::Debug for Codec<R> {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(fmt, "Codec") // TODO
    }
}

impl<R> Codec<R>
where
    R: RngCore + CryptoRng,
{
    pub(crate) fn new(rng: R, state: Arc<Mutex<State>>) -> Self {
        Self {
            rng,
            state,
            encrypt_state: EncryptState::Initial,
        }
    }
}

impl<R> Encoder for Codec<R>
where
    R: RngCore + CryptoRng,
{
    type Item = Bytes;
    type Error = CodecError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> CodecResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CodecError::UnabledToSharedStateLock)?;

        let item = state.comp_stoc().compress(&item)?;

        let len = item.len();
        let bs = state.encrypt_stoc().block_size();

        let pad = (1 + len + MINIMUM_PAD_SIZE) % bs;
        let pad = if pad > (bs - MINIMUM_PAD_SIZE) {
            bs * 2 - pad
        } else {
            bs - pad
        };
        let len = len + pad + 1;

        let mut pad = vec![0; pad];
        self.rng.fill_bytes(&mut pad);

        let mut unencrypted_pkt = BytesMut::with_capacity(len + 4);
        unencrypted_pkt.put_u32(len as u32);
        unencrypted_pkt.put_u8(pad.len() as u8);
        unencrypted_pkt.put_slice(&item);
        unencrypted_pkt.put_slice(&pad);
        let unencrypted_pkt = unencrypted_pkt.freeze();

        let encrypted = state.encrypt_stoc().encrypt(&unencrypted_pkt)?;

        let seq = state.get_and_inc_seq_stoc();
        let sign = state.mac_stoc().sign(seq, &unencrypted_pkt, &encrypted);
        dst.reserve(encrypted.len() + sign.len());
        dst.put(encrypted);
        dst.put(sign);
        Ok(())
    }
}

impl<R> Decoder for Codec<R>
where
    R: RngCore + CryptoRng,
{
    type Item = Packet;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> CodecResult<Option<Self::Item>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| CodecError::UnabledToSharedStateLock)?;
        let bs = state.encrypt_ctos().block_size();

        loop {
            match &self.encrypt_state {
                EncryptState::Initial => {
                    if src.len() < bs {
                        return Ok(None);
                    }
                    let encrypted_first = src.split_to(bs).freeze();
                    let first = state.encrypt_ctos().encrypt(&encrypted_first)?;
                    let len = first.clone().get_u32() as usize;
                    self.encrypt_state = EncryptState::FillBuffer {
                        encrypted_first,
                        first,
                        len,
                    };
                }
                EncryptState::FillBuffer {
                    encrypted_first,
                    first,
                    len,
                } => {
                    if src.len() < 4 || *len + 4 - bs > src.len() {
                        return Ok(None);
                    }
                    let encrypted_remaining = src.split_to(len + 4 - bs).freeze();
                    let remaining = state.encrypt_ctos().encrypt(&encrypted_remaining)?;

                    let mut encrypted =
                        BytesMut::with_capacity(encrypted_first.len() + encrypted_remaining.len());
                    encrypted.put(encrypted_first.as_ref());
                    encrypted.put(encrypted_remaining);
                    let encrypted = encrypted.freeze();

                    let mut plain = BytesMut::with_capacity(first.len() + remaining.len());
                    plain.put(first.as_ref());
                    plain.put(remaining);
                    let plain = plain.freeze();
                    self.encrypt_state = EncryptState::Sign { encrypted, plain };
                }
                EncryptState::Sign { encrypted, plain } => {
                    if src.len() < state.mac_ctos().size() {
                        return Ok(None);
                    }
                    let expect = src.split_to(state.mac_ctos().size());
                    let seq = state.get_and_inc_seq_ctos();
                    let sign = state.mac_ctos().sign(seq, &plain, &encrypted);
                    // TODO verify
                    if !openssl::memcmp::eq(&sign, &expect) {
                        panic!("ERR\n  {:?}\n  {:?}", &sign, &expect,);
                    }
                    let pad = plain[4] as usize;
                    let payload = plain.clone().split_off(5).split_to(plain.len() - pad);
                    let payload = state.comp_ctos().decompress(&payload)?;
                    self.encrypt_state = EncryptState::Initial;
                    return Ok(Some(Packet::new(seq, payload)));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::{SinkExt as _, TryStreamExt as _};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test() {
        let pkt = vec![
            0x00, 0x00, 0x00, 0x0c, // len
            0x0a, // pad len
            0x15, // payload (SSH_MSG_NEWKEYS)
            0xb2, 0xf7, 0xf5, 0x81, 0xd6, 0xde, 0x3c, 0x06, 0xa8, 0x22,
        ];

        let mut mock = Builder::new().read(&pkt).write(&pkt).build();
        let state = Arc::new(Mutex::new(State::new()));

        let mut codec = Codec::new(StdRng::seed_from_u64(0), state).framed(&mut mock);
        let b = codec.try_next().await.unwrap().unwrap().data();
        assert_eq!(b, Bytes::from(&[0x15][..]));

        codec.send(Bytes::from(b)).await.unwrap();
    }
}

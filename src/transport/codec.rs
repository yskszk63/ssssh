use std::io;

use bytes::{BufMut, Bytes, BytesMut};
use rand::{CryptoRng, RngCore};
use tokio::codec::{Decoder, Encoder};

const BLOCK_SIZE: usize = 8;
const MINIMUM_PAD_SIZE: usize = 4;

#[derive(Debug)]
pub enum CodecError {
    Io(io::Error),
}

impl From<io::Error> for CodecError {
    fn from(v: io::Error) -> Self {
        CodecError::Io(v)
    }
}

pub type CodecResult<T> = Result<T, CodecError>;

enum CodecState {
    Plain,
    Encrypt {
        ctos_enc: openssl::symm::Crypter,
        stoc_enc: openssl::symm::Crypter,
        ctos_int: Bytes,
        stoc_int: Bytes,
    },
}

impl std::fmt::Debug for CodecState {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CodecState::Plain => write!(fmt, "Plain"),
            CodecState::Encrypt{..} => write!(fmt, "Encrypt"),
        }
    }
}

#[derive(Debug)]
pub struct Codec<R>
where
    R: RngCore + CryptoRng,
{
    state: CodecState,
    rng: R,
    seq_ctos: u32,
    seq_stoc: u32,
}

impl<R> Codec<R>
where
    R: RngCore + CryptoRng,
{
    pub fn new(rng: R) -> Self {
        Codec { state: CodecState::Plain, rng, seq_ctos: 0, seq_stoc: 0, }
    }

    pub fn change_key(&mut self, hash: Bytes, secret: Bytes) {
        use crate::sshbuf::SshBufMut as _;

        let mut iv_ctos = BytesMut::with_capacity(1024 * 8);
        iv_ctos.put_mpint(&secret).unwrap();
        iv_ctos.put_slice(&hash);
        iv_ctos.put_u8(b'A');
        iv_ctos.put_slice(&hash);
        let iv_ctos = sodiumoxide::crypto::hash::sha256::hash(&iv_ctos);

        let mut key_ctos = BytesMut::with_capacity(1024 * 8);
        key_ctos.put_mpint(&secret).unwrap();
        key_ctos.put_slice(&hash);
        key_ctos.put_u8(b'C');
        key_ctos.put_slice(&hash);
        let key_ctos = sodiumoxide::crypto::hash::sha256::hash(&key_ctos);

        let crypter_ctos = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_256_ctr(),
            openssl::symm::Mode::Decrypt,
            &key_ctos.0,
            Some(&iv_ctos.0[..16]),
            ).unwrap();

        let mut iv_stoc = BytesMut::with_capacity(1024 * 8);
        iv_stoc.put_mpint(&secret).unwrap();
        iv_stoc.put_slice(&hash);
        iv_stoc.put_u8(b'B');
        iv_stoc.put_slice(&hash);
        let iv_stoc = sodiumoxide::crypto::hash::sha256::hash(&iv_stoc);

        let mut key_stoc = BytesMut::with_capacity(1024 * 8);
        key_stoc.put_mpint(&secret).unwrap();
        key_stoc.put_slice(&hash);
        key_stoc.put_u8(b'D');
        key_stoc.put_slice(&hash);
        let key_stoc = sodiumoxide::crypto::hash::sha256::hash(&key_stoc);

        let crypter_stoc = openssl::symm::Crypter::new(
            openssl::symm::Cipher::aes_256_ctr(),
            openssl::symm::Mode::Encrypt,
            &key_stoc.0,
            Some(&iv_stoc.0[..16]),
            ).unwrap();

        let mut intk_ctos = BytesMut::with_capacity(1024 * 8);
        intk_ctos.put_mpint(&secret).unwrap();
        intk_ctos.put_slice(&hash);
        intk_ctos.put_u8(b'E');
        intk_ctos.put_slice(&hash);
        let intk_ctos = sodiumoxide::crypto::hash::sha256::hash(&intk_ctos);

        let mut intk_stoc = BytesMut::with_capacity(1024 * 8);
        intk_stoc.put_mpint(&secret).unwrap();
        intk_stoc.put_slice(&hash);
        intk_stoc.put_u8(b'F');
        intk_stoc.put_slice(&hash);
        let intk_stoc = sodiumoxide::crypto::hash::sha256::hash(&intk_stoc);

        self.state = CodecState::Encrypt {
            ctos_enc: crypter_ctos,
            stoc_enc: crypter_stoc,
            ctos_int: Bytes::from(&intk_ctos.0[..]),
            stoc_int: Bytes::from(&intk_stoc.0[..]),
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
        fn encode<R>(item: Bytes, dst: &mut BytesMut, rng: &mut R) -> CodecResult<()> where R: RngCore + CryptoRng {
            let len = item.len();
            let pad = (1 + len + MINIMUM_PAD_SIZE) % BLOCK_SIZE;
            let pad = if pad > (BLOCK_SIZE - MINIMUM_PAD_SIZE) {
                BLOCK_SIZE * 2 - pad
            } else {
                BLOCK_SIZE - pad
            };
            let len = len + pad + 1;

            let mut pad = vec![0; pad];
            rng.fill_bytes(&mut pad);

            dst.put_u32_be(len as u32);
            dst.put_u8(pad.len() as u8);
            dst.put_slice(&item);
            dst.put_slice(&pad);
            Ok(())
        }

        match self.state {
            CodecState::Plain => {
                encode(item, dst, &mut self.rng)?;
            },
            CodecState::Encrypt {ref mut stoc_enc, ref mut stoc_int, ..} => {
                let mut b = BytesMut::with_capacity(1024 * 8);
                encode(item, &mut b, &mut self.rng)?;
                let mut b2 = [0; 128];
                let c = stoc_enc.update(&b, &mut b2).unwrap();
                dst.put_slice(&b2[..c]);

                let key = openssl::pkey::PKey::hmac(&stoc_int).unwrap();
                let mut signer = openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
                let seq = self.seq_stoc;
                signer.update(&[
                    (seq>> 24) as u8,
                    (seq >> 16) as u8,
                    (seq >> 8) as u8,
                    (seq >> 0) as u8,
                ]).unwrap();
                signer.update(&b).unwrap();
                dst.put_slice(&signer.sign_to_vec().unwrap());
            }
        }
        self.seq_stoc += 1;
        Ok(())
    }
}

impl<R> Decoder for Codec<R>
where
    R: RngCore + CryptoRng,
{
    type Item = Bytes;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> CodecResult<Option<Self::Item>> {
        fn len(src: &BytesMut) -> Option<u32> {
            if src.len() < 4 {
                return None;
            };

            let len = (src[0] as u32) << 24
                | (src[1] as u32) << 16
                | (src[2] as u32) << 8
                | (src[3] as u32) << 0;
            Some(len)
        }

        fn decode(src: &mut BytesMut) -> CodecResult<Option<Bytes>> {
            let len = match len(src) {
                Some(e) => e as usize,
                None => return Ok(None),
            };
            if src.len() < len + 4 {
                return Ok(None);
            }
            src.advance(4);
            let mut src = src.split_to(len);
            let pad = src[0] as usize;
            src.advance(1);

            let payload = src.split_to(len - 1 - pad).freeze();
            let _pad = src.split_to(pad);

            Ok(Some(payload))
        }

        let result = match &mut self.state {
            CodecState::Plain => decode(src)?,
            CodecState::Encrypt {ref mut ctos_enc, ref mut ctos_int, .. } => {
                if src.len() == 0 {
                    return Ok(None)
                }
                let mut buf = [0; 128];
                let c = ctos_enc.update(&src.split_to(32), &mut buf).unwrap();

                let key = openssl::pkey::PKey::hmac(&ctos_int).unwrap();
                let mut signer =
                    openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key).unwrap();
                let seq = self.seq_ctos;
                signer.update(&[
                    (seq >> 24) as u8,
                    (seq >> 16) as u8,
                    (seq >> 8) as u8,
                    (seq >> 0) as u8,
                ]).unwrap();
                signer.update(&buf[..c]).unwrap();
                let expect = src.split_to(signer.len().unwrap());
                if !openssl::memcmp::eq(&Bytes::from(&signer.sign_to_vec().unwrap()[..]), &expect) {
                    panic!("ERR\n  {:?}\n  {:?}", &Bytes::from(&signer.sign_to_vec().unwrap()[..]), &expect);
                }

                let mut src = BytesMut::from(&buf[..c]);
                decode(&mut src)?
            }
        };

        match result {
            Some(e) => {
                self.seq_ctos += 1;
                Ok(Some(e))
            },
            None => Ok(None),
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

        let mut codec = Codec::new(StdRng::seed_from_u64(0)).framed(&mut mock);
        let b = codec.try_next().await.unwrap().unwrap();
        assert_eq!(b, Bytes::from(&[0x15][..]));

        codec.send(Bytes::from(b)).await.unwrap();
    }
}

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

#[derive(Debug)]
pub struct Codec<R>
where
    R: RngCore + CryptoRng,
{
    rng: R,
}

impl<R> Codec<R>
where
    R: RngCore + CryptoRng,
{
    pub fn new(rng: R) -> Self {
        Codec { rng }
    }
}

impl<R> Encoder for Codec<R>
where
    R: RngCore + CryptoRng,
{
    type Item = Bytes;
    type Error = CodecError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> CodecResult<()> {
        let len = item.len();
        let pad = (1 + len + MINIMUM_PAD_SIZE) % BLOCK_SIZE;
        let pad = if pad > (BLOCK_SIZE - MINIMUM_PAD_SIZE) {
            BLOCK_SIZE * 2 - pad
        } else {
            BLOCK_SIZE - pad
        };
        let len = len + pad + 1;

        let mut pad = vec![0; pad];
        self.rng.fill_bytes(&mut pad);

        dst.put_u32_be(len as u32);
        dst.put_u8(pad.len() as u8);
        dst.put_slice(&item);
        dst.put_slice(&pad);
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

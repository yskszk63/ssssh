use std::io;

use bytes::{Buf, BufMut, Bytes, BytesMut};
use openssl::hash::MessageDigest;
use rand::{CryptoRng, RngCore};
use tokio::codec::{Decoder, Encoder};

use crate::algorithm::{
    Algorithm, CompressionAlgorithm, EncryptionAlgorithm, KexAlgorithm, MacAlgorithm,
};
use crate::compression::{Compression, NoneCompression};
use crate::encrypt::{Aes256CtrEncrypt, Encrypt, PlainEncrypt};
use crate::mac::{HmacSha2_256, Mac, NoneMac};
use crate::sshbuf::SshBufMut as _;

const MINIMUM_PAD_SIZE: usize = 4;

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum CodecError {
    Io(io::Error),
}

impl From<io::Error> for CodecError {
    fn from(v: io::Error) -> Self {
        Self::Io(v)
    }
}

#[allow(clippy::module_name_repetitions)]
pub type CodecResult<T> = Result<T, CodecError>;

fn calculate_hash(
    hash: &[u8],
    key: &[u8],
    kind: u8,
    session_id: &[u8],
    algorithm: &Algorithm,
    len: usize,
) -> Bytes {
    let mut content = BytesMut::with_capacity(1024 * 8);
    content.put_mpint(key).unwrap();
    content.put_slice(hash);
    content.put_u8(kind);
    content.put_slice(session_id);

    let hash_fn = match algorithm.kex_algorithm() {
        KexAlgorithm::Curve25519Sha256 => MessageDigest::sha256(),
    };
    openssl::hash::hash(hash_fn, &content).unwrap()[..len]
        .iter()
        .collect()
}

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

pub struct Codec<R>
where
    R: RngCore + CryptoRng,
{
    rng: R,
    seq_ctos: u32,
    seq_stoc: u32,
    session_id: Option<Bytes>,
    encrypt_ctos: Box<dyn Encrypt + Send>,
    encrypt_stoc: Box<dyn Encrypt + Send>,
    mac_ctos: Box<dyn Mac + Send>,
    mac_stoc: Box<dyn Mac + Send>,
    comp_ctos: Box<dyn Compression + Send>,
    comp_stoc: Box<dyn Compression + Send>,
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
    pub fn new(rng: R) -> Self {
        Self {
            rng,
            seq_ctos: 0,
            seq_stoc: 0,
            session_id: None,
            encrypt_ctos: Box::new(PlainEncrypt),
            encrypt_stoc: Box::new(PlainEncrypt),
            mac_ctos: Box::new(NoneMac),
            mac_stoc: Box::new(NoneMac),
            comp_ctos: Box::new(NoneCompression),
            comp_stoc: Box::new(NoneCompression),
            encrypt_state: EncryptState::Initial,
        }
    }

    pub fn change_key(&mut self, hash: &Bytes, secret: &Bytes, algorithm: &Algorithm) {
        match &self.encrypt_state {
            EncryptState::Initial => {}
            e => panic!("{:?}", e),
        }

        let session_id = self.session_id.as_ref().unwrap_or_else(|| &hash);

        let iv_ctos = calculate_hash(&hash, &secret, b'A', session_id, &algorithm, 16);
        let iv_stoc = calculate_hash(&hash, &secret, b'B', session_id, &algorithm, 16);

        let key_ctos = calculate_hash(&hash, &secret, b'C', session_id, &algorithm, 32);
        let key_stoc = calculate_hash(&hash, &secret, b'D', session_id, &algorithm, 32);

        let intk_ctos = calculate_hash(&hash, &secret, b'E', session_id, &algorithm, 32);
        let intk_stoc = calculate_hash(&hash, &secret, b'F', session_id, &algorithm, 32);

        self.encrypt_ctos = match algorithm.encryption_algorithm_client_to_server() {
            EncryptionAlgorithm::Aes256Ctr => {
                Box::new(Aes256CtrEncrypt::new_for_decrypt(&key_ctos, &iv_ctos))
            }
        };

        self.encrypt_stoc = match algorithm.encryption_algorithm_server_to_client() {
            EncryptionAlgorithm::Aes256Ctr => {
                Box::new(Aes256CtrEncrypt::new_for_encrypt(&key_stoc, &iv_stoc))
            }
        };

        self.mac_ctos = match algorithm.mac_algorithm_client_to_server() {
            MacAlgorithm::HmacSha2_256 => Box::new(HmacSha2_256::new(&intk_ctos)),
        };

        self.mac_stoc = match algorithm.mac_algorithm_server_to_client() {
            MacAlgorithm::HmacSha2_256 => Box::new(HmacSha2_256::new(&intk_stoc)),
        };

        self.comp_ctos = match algorithm.compression_algorithm_client_to_server() {
            CompressionAlgorithm::None => Box::new(NoneCompression),
        };

        self.comp_stoc = match algorithm.compression_algorithm_server_to_client() {
            CompressionAlgorithm::None => Box::new(NoneCompression),
        };

        self.session_id = Some(hash.clone());
    }
}

impl<R> Encoder for Codec<R>
where
    R: RngCore + CryptoRng,
{
    type Item = Bytes;
    type Error = CodecError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> CodecResult<()> {
        let enc = &mut self.encrypt_stoc;
        let mac = &self.mac_stoc;

        let item = self.comp_stoc.compress(&item).unwrap();

        let len = item.len();
        let bs = enc.block_size();

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
        unencrypted_pkt.put_u32_be(len as u32);
        unencrypted_pkt.put_u8(pad.len() as u8);
        unencrypted_pkt.put_slice(&item);
        unencrypted_pkt.put_slice(&pad);
        let unencrypted_pkt = unencrypted_pkt.freeze();

        let encrypted = enc.encrypt(&unencrypted_pkt).unwrap();

        let sign = mac
            .sign(self.seq_stoc, &unencrypted_pkt, &encrypted)
            .unwrap();
        self.seq_stoc += 1;
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
    type Item = Bytes;
    type Error = CodecError;

    fn decode(&mut self, src: &mut BytesMut) -> CodecResult<Option<Self::Item>> {
        let enc = &mut self.encrypt_ctos;
        let mac = &mut self.mac_ctos;
        let bs = enc.block_size();

        loop {
            match &self.encrypt_state {
                EncryptState::Initial => {
                    if src.len() < bs {
                        return Ok(None);
                    }
                    let encrypted_first = src.split_to(bs).freeze();
                    let first = enc.encrypt(&encrypted_first).unwrap();
                    let len = io::Cursor::new(&first).get_u32_be() as usize;
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
                    let remaining = enc.encrypt(&encrypted_remaining).unwrap();

                    let mut encrypted =
                        BytesMut::with_capacity(encrypted_first.len() + encrypted_remaining.len());
                    encrypted.put(encrypted_first);
                    encrypted.put(encrypted_remaining);
                    let encrypted = encrypted.freeze();

                    let mut plain = BytesMut::with_capacity(first.len() + remaining.len());
                    plain.put(first);
                    plain.put(remaining);
                    let plain = plain.freeze();
                    self.encrypt_state = EncryptState::Sign { encrypted, plain };
                }
                EncryptState::Sign { encrypted, plain } => {
                    if src.len() < mac.size() {
                        return Ok(None);
                    }
                    let expect = src.split_to(mac.size());
                    let sign = mac.sign(self.seq_ctos, &plain, &encrypted).unwrap();
                    if !openssl::memcmp::eq(&sign, &expect) {
                        panic!("ERR\n  {:?}\n  {:?}", &sign, &expect,);
                    }
                    let pad = plain[4] as usize;
                    let payload = plain.slice(5, plain.len() - pad);
                    let payload = self.comp_ctos.decompress(&payload).unwrap();
                    self.seq_ctos += 1;
                    self.encrypt_state = EncryptState::Initial;
                    return Ok(Some(payload));
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

        let mut codec = Codec::new(StdRng::seed_from_u64(0)).framed(&mut mock);
        let b = codec.try_next().await.unwrap().unwrap();
        assert_eq!(b, Bytes::from(&[0x15][..]));

        codec.send(Bytes::from(b)).await.unwrap();
    }
}

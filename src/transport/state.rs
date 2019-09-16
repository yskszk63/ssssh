use std::fmt;

use bytes::{BufMut as _, Bytes, BytesMut};
use failure::Fail;
use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256};

use crate::algorithm::{Algorithm, CompressionAlgorithm, EncryptionAlgorithm, KexAlgorithm};
use crate::compression::{Compression, NoneCompression};
use crate::encrypt::{Aes256CtrEncrypt, Encrypt, EncryptError, PlainEncrypt};
use crate::mac::Mac;
use crate::sshbuf::SshBufMut as _;

#[derive(Debug, Fail)]
pub(crate) enum ChangeKeyError {
    #[fail(display = "EncryptError")]
    EncryptError(#[fail(cause)] EncryptError),
}

impl From<EncryptError> for ChangeKeyError {
    fn from(v: EncryptError) -> Self {
        Self::EncryptError(v)
    }
}

fn calculate_hash(
    hash: &[u8],
    key: &[u8],
    kind: u8,
    session_id: &[u8],
    algorithm: &Algorithm,
    len: usize,
) -> Bytes {
    let alg = match algorithm.kex_algorithm() {
        KexAlgorithm::Curve25519Sha256 => &SHA256,
        KexAlgorithm::DiffieHellmanGroup14Sha1 => &SHA1,
    };
    let mut ctx = Context::new(alg);
    ctx.put_mpint(key);
    ctx.update(hash);
    ctx.update(&[kind]);
    ctx.update(session_id);
    let mut result = BytesMut::from(ctx.finish().as_ref());

    while result.len() < len {
        let last = result.clone().freeze();
        let mut ctx = Context::new(alg);
        ctx.put_mpint(key);
        ctx.update(hash);
        ctx.update(&last);
        let k = ctx.finish();
        result.reserve(result.len() + k.as_ref().len());
        result.put(k.as_ref());
    }

    result.freeze().slice_to(len)
}

pub(crate) struct State {
    seq_ctos: u32,
    seq_stoc: u32,
    session_id: Option<Bytes>,
    encrypt_ctos: Box<dyn Encrypt + Send>,
    encrypt_stoc: Box<dyn Encrypt + Send>,
    mac_ctos: Mac,
    mac_stoc: Mac,
    comp_ctos: Box<dyn Compression + Send>,
    comp_stoc: Box<dyn Compression + Send>,
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "State")
    }
}

impl State {
    pub(crate) fn new() -> Self {
        Self {
            seq_ctos: 0,
            seq_stoc: 0,
            session_id: None,
            encrypt_ctos: Box::new(PlainEncrypt),
            encrypt_stoc: Box::new(PlainEncrypt),
            mac_ctos: Mac::new_none(),
            mac_stoc: Mac::new_none(),
            comp_ctos: Box::new(NoneCompression),
            comp_stoc: Box::new(NoneCompression),
        }
    }

    pub(crate) fn get_and_inc_seq_ctos(&mut self) -> u32 {
        let r = self.seq_ctos;
        self.seq_ctos += 1;
        r
    }

    pub(crate) fn get_and_inc_seq_stoc(&mut self) -> u32 {
        let r = self.seq_stoc;
        self.seq_stoc += 1;
        r
    }

    pub(crate) fn encrypt_ctos(&mut self) -> &mut Box<dyn Encrypt + Send> {
        &mut self.encrypt_ctos
    }

    pub(crate) fn encrypt_stoc(&mut self) -> &mut Box<dyn Encrypt + Send> {
        &mut self.encrypt_stoc
    }

    pub(crate) fn mac_ctos(&mut self) -> &mut Mac {
        &mut self.mac_ctos
    }

    pub(crate) fn mac_stoc(&mut self) -> &mut Mac {
        &mut self.mac_stoc
    }

    pub(crate) fn comp_ctos(&mut self) -> &mut Box<dyn Compression + Send> {
        &mut self.comp_ctos
    }

    pub(crate) fn comp_stoc(&mut self) -> &mut Box<dyn Compression + Send> {
        &mut self.comp_stoc
    }

    pub(crate) fn change_key(
        &mut self,
        hash: &Bytes,
        secret: &Bytes,
        algorithm: &Algorithm,
    ) -> Result<(), ChangeKeyError> {
        let session_id = self.session_id.as_ref().unwrap_or_else(|| &hash);

        let iv_ctos = calculate_hash(&hash, &secret, b'A', session_id, &algorithm, 16);
        let iv_stoc = calculate_hash(&hash, &secret, b'B', session_id, &algorithm, 16);

        let key_ctos = calculate_hash(&hash, &secret, b'C', session_id, &algorithm, 32);
        let key_stoc = calculate_hash(&hash, &secret, b'D', session_id, &algorithm, 32);

        let intk_ctos = calculate_hash(&hash, &secret, b'E', session_id, &algorithm, 32);
        let intk_stoc = calculate_hash(&hash, &secret, b'F', session_id, &algorithm, 32);

        self.encrypt_ctos = match algorithm.encryption_algorithm_client_to_server() {
            EncryptionAlgorithm::Aes256Ctr => {
                Box::new(Aes256CtrEncrypt::new_for_decrypt(&key_ctos, &iv_ctos)?)
                // TODO
            }
        };

        self.encrypt_stoc = match algorithm.encryption_algorithm_server_to_client() {
            EncryptionAlgorithm::Aes256Ctr => {
                Box::new(Aes256CtrEncrypt::new_for_encrypt(&key_stoc, &iv_stoc)?)
            }
        };

        self.mac_ctos = Mac::new(&algorithm.mac_algorithm_client_to_server(), &intk_ctos);
        self.mac_stoc = Mac::new(&algorithm.mac_algorithm_server_to_client(), &intk_stoc);

        self.comp_ctos = match algorithm.compression_algorithm_client_to_server() {
            CompressionAlgorithm::None => Box::new(NoneCompression),
        };

        self.comp_stoc = match algorithm.compression_algorithm_server_to_client() {
            CompressionAlgorithm::None => Box::new(NoneCompression),
        };

        self.session_id = Some(hash.clone());
        Ok(())
    }
}

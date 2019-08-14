use bytes::Bytes;
use futures::{Sink, TryStream};

use crate::algorithm::KexAlgorithm;
use crate::hostkey::HostKey;
use crate::msg::{Kexinit, Message, MessageError};

mod ecdh;

#[derive(Debug)]
pub struct KexEnv<'a, Tx, Rx>
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = Message, Error = MessageError> + Unpin,
{
    tx: &'a mut Tx,
    rx: &'a mut Rx,
    client_version: &'a [u8],
    server_version: &'a [u8],
    client_kexinit: &'a Kexinit,
    server_kexinit: &'a Kexinit,
    hostkey: &'a HostKey,
}

impl<'a, Tx, Rx> KexEnv<'a, Tx, Rx>
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = Message, Error = MessageError> + Unpin,
{
    pub fn new(
        tx: &'a mut Tx,
        rx: &'a mut Rx,
        client_version: &'a [u8],
        server_version: &'a [u8],
        client_kexinit: &'a Kexinit,
        server_kexinit: &'a Kexinit,
        hostkey: &'a HostKey,
    ) -> Self {
        Self {
            tx,
            rx,
            client_kexinit,
            server_kexinit,
            client_version,
            server_version,
            hostkey,
        }
    }
}

pub type KexResult = Result<KexReturn, KexError>;

#[derive(Debug)]
pub enum KexError {
    ProtocolError,
    MessageError(MessageError),
}

impl From<MessageError> for KexError {
    fn from(v: MessageError) -> Self {
        Self::MessageError(v)
    }
}

#[derive(Debug)]
pub struct KexReturn {
    hash: Bytes,
    key: Bytes,
}

impl KexReturn {
    pub fn split(self) -> (Bytes, Bytes) {
        (self.hash, self.key)
    }
}

pub async fn kex<Tx, Rx>(algorithm: &KexAlgorithm, env: &mut KexEnv<'_, Tx, Rx>) -> KexResult
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = Message, Error = MessageError> + Unpin,
{
    match algorithm {
        KexAlgorithm::Curve25519Sha256 => ecdh::kex_ecdh(env).await,
    }
}

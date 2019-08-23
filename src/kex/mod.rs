use bytes::Bytes;
use futures::{Sink, TryStream};

use crate::algorithm::KexAlgorithm;
use crate::hostkey::HostKey;
use crate::msg::{Kexinit, Message, MessageError};
use crate::transport::version::Version;

mod ecdh;

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub(crate) struct KexEnv<'a, Tx, Rx>
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = Message, Error = MessageError> + Unpin,
{
    tx: &'a mut Tx,
    rx: &'a mut Rx,
    version: &'a Version,
    client_kexinit: &'a Kexinit,
    server_kexinit: &'a Kexinit,
    hostkey: &'a HostKey,
}

impl<'a, Tx, Rx> KexEnv<'a, Tx, Rx>
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = Message, Error = MessageError> + Unpin,
{
    pub(crate) fn new(
        tx: &'a mut Tx,
        rx: &'a mut Rx,
        version: &'a Version,
        client_kexinit: &'a Kexinit,
        server_kexinit: &'a Kexinit,
        hostkey: &'a HostKey,
    ) -> Self {
        Self {
            tx,
            rx,
            version,
            client_kexinit,
            server_kexinit,
            hostkey,
        }
    }
}

#[allow(clippy::module_name_repetitions)]
pub(crate) type KexResult = Result<KexReturn, KexError>;

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub(crate) enum KexError {
    ProtocolError,
    MessageError(MessageError),
}

impl From<MessageError> for KexError {
    fn from(v: MessageError) -> Self {
        Self::MessageError(v)
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub(crate) struct KexReturn {
    hash: Bytes,
    key: Bytes,
}

impl KexReturn {
    pub fn split(self) -> (Bytes, Bytes) {
        (self.hash, self.key)
    }
}

pub(crate) async fn kex<Tx, Rx>(algorithm: &KexAlgorithm, env: &mut KexEnv<'_, Tx, Rx>) -> KexResult
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = Message, Error = MessageError> + Unpin,
{
    match algorithm {
        KexAlgorithm::Curve25519Sha256 => ecdh::kex_ecdh(env).await,
    }
}

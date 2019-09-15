use bytes::Bytes;
use failure::Fail;
use futures::{Sink, TryStream};

use crate::algorithm::KexAlgorithm;
use crate::hostkey::HostKey;
use crate::msg::{Kexinit, Message, MessageError};
use crate::transport::version::Version;

mod diffie_hellman_group14_sha1;
mod ecdh;

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub(crate) struct KexEnv<'a, Tx, Rx>
where
    Tx: Sink<Message, Error = MessageError> + Unpin,
    Rx: TryStream<Ok = (u32, Message), Error = MessageError> + Unpin,
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
    Rx: TryStream<Ok = (u32, Message), Error = MessageError> + Unpin,
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

#[derive(Debug, Fail)]
#[allow(clippy::module_name_repetitions)]
pub(crate) enum KexError {
    #[fail(display = "ProtocolError")]
    ProtocolError,
    #[fail(display = "MessageError")]
    MessageError(#[fail(cause)] MessageError),
    #[fail(display = "Other Error")]
    Other,
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
    Rx: TryStream<Ok = (u32, Message), Error = MessageError> + Unpin,
{
    match algorithm {
        KexAlgorithm::Curve25519Sha256 => ecdh::kex_ecdh(env).await,
        KexAlgorithm::DiffieHellmanGroup14Sha1 => diffie_hellman_group14_sha1::kex_dh(env).await,
    }
}

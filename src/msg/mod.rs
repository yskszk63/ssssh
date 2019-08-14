use std::convert::TryFrom;
use std::string::FromUtf8Error;

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut, IntoBuf as _};

use crate::sshbuf::SshBufError;
use crate::transport::codec::CodecError;
pub use id::*;
pub use kex_ecdh_init::*;
pub use kex_ecdh_reply::*;
pub use kexinit::*;
pub use newkeys::*;
pub use service_accept::*;
pub use service_request::*;

mod id;
mod kex_ecdh_init;
mod kex_ecdh_reply;
mod kexinit;
mod newkeys;
mod service_accept;
mod service_request;

#[derive(Debug)]
pub enum MessageError {
    UnknownMessageId(u8),
    Unimplemented(MessageId),
    Underflow,
    Overflow,
    FromUtf8Error(FromUtf8Error),
    Codec(CodecError),
}

impl From<UnknownMessageId> for MessageError {
    fn from(v: UnknownMessageId) -> Self {
        Self::UnknownMessageId(v.id())
    }
}

impl From<SshBufError> for MessageError {
    fn from(v: SshBufError) -> Self {
        match v {
            SshBufError::FromUtf8Error(e) => Self::FromUtf8Error(e),
            SshBufError::Overflow => Self::Overflow,
            SshBufError::Underflow => Self::Underflow,
        }
    }
}

impl From<CodecError> for MessageError {
    fn from(v: CodecError) -> Self {
        Self::Codec(v)
    }
}

pub type MessageResult<T> = Result<T, MessageError>;

#[derive(Debug)]
pub enum Message {
    Kexinit(Kexinit),
    KexEcdhInit(KexEcdhInit),
    KexEcdhReply(KexEcdhReply),
    Newkeys(Newkeys),
    ServiceRequest(ServiceRequest),
}

impl Message {
    fn id(&self) -> MessageId {
        match self {
            Message::Kexinit(..) => MessageId::Kexinit,
            Message::KexEcdhInit(..) => MessageId::KexEcdhInit,
            Message::KexEcdhReply(..) => MessageId::KexEcdhReply,
            Message::Newkeys(..) => MessageId::Newkeys,
            Message::ServiceRequest(..) => MessageId::ServiceRequest,
        }
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_u8(self.id() as u8);
        match self {
            Message::Kexinit(v) => v.put(buf)?,
            Message::KexEcdhInit(v) => v.put(buf)?,
            Message::KexEcdhReply(v) => v.put(buf)?,
            Message::Newkeys(v) => v.put(buf)?,
            Message::ServiceRequest(v) => v.put(buf)?,
        };
        Ok(())
    }
}

impl TryFrom<Bytes> for Message {
    type Error = MessageError;

    fn try_from(v: Bytes) -> MessageResult<Message> {
        let mut buf = v.into_buf();
        let message_id = MessageId::try_from(buf.get_u8())?;
        Ok(match message_id {
            MessageId::Kexinit => Kexinit::from(buf)?.into(),
            MessageId::KexEcdhInit => KexEcdhInit::from(buf)?.into(),
            MessageId::KexEcdhReply => KexEcdhReply::from(buf)?.into(),
            MessageId::Newkeys => Newkeys::from(buf)?.into(),
            MessageId::ServiceRequest => ServiceRequest::from(buf)?.into(),
            message_id => return Err(MessageError::Unimplemented(message_id)),
        })
    }
}

use std::convert::TryFrom;
use std::string::FromUtf8Error;

use bytes::{Buf as _, Bytes, BytesMut, IntoBuf as _};

use crate::sshbuf::SshBufError;
use crate::transport::codec::CodecError;
pub use id::*;
pub use kex_edch_init::*;
pub use kex_edch_reply::*;
pub use kexinit::*;
pub use newkeys::*;

mod id;
mod kex_edch_init;
mod kex_edch_reply;
mod kexinit;
mod newkeys;

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
    Kexinit(kexinit::Kexinit),
    KexEdchInit(kex_edch_init::KexEdchInit),
    KexEdchReply(kex_edch_reply::KexEdchReply),
    Newkeys(newkeys::Newkeys),
}

impl Message {
    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        match self {
            Message::Kexinit(v) => v.put(buf)?,
            Message::KexEdchInit(v) => v.put(buf)?,
            Message::KexEdchReply(v) => v.put(buf)?,
            Message::Newkeys(v) => v.put(buf)?,
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
            MessageId::KexEcdhInit => KexEdchInit::from(buf)?.into(),
            MessageId::KexEcdhReply => KexEdchReply::from(buf)?.into(),
            MessageId::Newkeys => Newkeys::from(buf)?.into(),
            message_id => return Err(MessageError::Unimplemented(message_id)),
        })
    }
}

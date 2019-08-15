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
pub use userauth_request::*;
pub use userauth_failure::*;
pub use userauth_success::*;
pub use channel_open::*;
pub use channel_open_confirmation::*;
pub use channel_request::*;
pub use channel_failure::*;
pub use channel_success::*;
pub use channel_data::*;
pub use channel_eof::*;
pub use channel_close::*;
pub use disconnect::*;
pub use ignore::*;
pub use debug::*;
pub use unimplemented::*;
pub use userauth_banner::*;
pub use global_request::*;
pub use request_success::*;
pub use request_failure::*;
pub use channel_open_failure::*;
pub use channel_window_adjust::*;
pub use channel_extended_data::*;

mod id;
mod kex_ecdh_init;
mod kex_ecdh_reply;
mod kexinit;
mod newkeys;
mod service_accept;
mod service_request;
mod userauth_request;
mod userauth_failure;
mod userauth_success;
mod channel_open;
mod channel_open_confirmation;
mod channel_request;
mod channel_failure;
mod channel_success;
mod channel_data;
mod channel_eof;
mod channel_close;
mod disconnect;
mod ignore;
mod debug;
mod unimplemented;
mod userauth_banner;
mod global_request;
mod request_success;
mod request_failure;
mod channel_open_failure;
mod channel_window_adjust;
mod channel_extended_data;

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
    ServiceAccept(ServiceAccept),
    UserauthRequest(UserauthRequest),
    UserauthFailure(UserauthFailure),
    UserauthSuccess(UserauthSuccess),
    ChannelOpen(ChannelOpen),
    ChannelOpenConfirmation(ChannelOpenConfirmation),
    ChannelRequest(ChannelRequest),
    ChannelFailure(ChannelFailure),
    ChannelSuccess(ChannelSuccess),
    ChannelData(ChannelData),
    ChannelEof(ChannelEof),
    ChannelClose(ChannelClose),
    Disconnect(Disconnect),
    Ignore(Ignore),
    Debug(Debug),
    Unimplemented(Unimplemented),
    UserauthBanner(UserauthBanner),
    GlobalRequest(GlobalRequest),
    RequestSuccess(RequestSuccess),
    RequestFailure(RequestFailure),
    ChannelOpenFailure(ChannelOpenFailure),
    ChannelWindowAdjust(ChannelWindowAdjust),
    ChannelExtendedData(ChannelExtendedData),
}

impl Message {
    fn id(&self) -> MessageId {
        match self {
            Message::Kexinit(..) => MessageId::Kexinit,
            Message::KexEcdhInit(..) => MessageId::KexEcdhInit,
            Message::KexEcdhReply(..) => MessageId::KexEcdhReply,
            Message::Newkeys(..) => MessageId::Newkeys,
            Message::ServiceRequest(..) => MessageId::ServiceRequest,
            Message::ServiceAccept(..) => MessageId::ServiceAccept,
            Message::UserauthRequest(..) => MessageId::UserauthRequest,
            Message::UserauthFailure(..) => MessageId::UserauthFailure,
            Message::UserauthSuccess(..) => MessageId::UserauthSuccess,
            Message::ChannelOpen(..) => MessageId::ChannelOpen,
            Message::ChannelOpenConfirmation(..) => MessageId::ChannelOpenConfirmation,
            Message::ChannelRequest(..) => MessageId::ChannelRequest,
            Message::ChannelFailure(..) => MessageId::ChannelFailure,
            Message::ChannelSuccess(..) => MessageId::ChannelSuccess,
            Message::ChannelData(..) => MessageId::ChannelData,
            Message::ChannelEof(..) => MessageId::ChannelEof,
            Message::ChannelClose(..) => MessageId::ChannelClose,
            Message::Disconnect(..) => MessageId::Disconnect,
            Message::Ignore(..) => MessageId::Ignore,
            Message::Debug(..) => MessageId::Debug,
            Message::Unimplemented(..) => MessageId::Unimplemented,
            Message::UserauthBanner(..) => MessageId::UserauthBanner,
            Message::GlobalRequest(..) => MessageId::GlobalRequest,
            Message::RequestSuccess(..) => MessageId::RequestSuccess,
            Message::RequestFailure(..) => MessageId::RequestFailure,
            Message::ChannelOpenFailure(..) => MessageId::ChannelOpenFailure,
            Message::ChannelWindowAdjust(..) => MessageId::ChannelWindowAdjust,
            Message::ChannelExtendedData(..) => MessageId::ChannelExtendedData,
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
            Message::ServiceAccept(v) => v.put(buf)?,
            Message::UserauthRequest(v) => v.put(buf)?,
            Message::UserauthFailure(v) => v.put(buf)?,
            Message::UserauthSuccess(v) => v.put(buf)?,
            Message::ChannelOpen(v) => v.put(buf)?,
            Message::ChannelOpenConfirmation(v) => v.put(buf)?,
            Message::ChannelRequest(v) => v.put(buf)?,
            Message::ChannelFailure(v) => v.put(buf)?,
            Message::ChannelSuccess(v) => v.put(buf)?,
            Message::ChannelData(v) => v.put(buf)?,
            Message::ChannelEof(v) => v.put(buf)?,
            Message::ChannelClose(v) => v.put(buf)?,
            Message::Disconnect(v) => v.put(buf)?,
            Message::Ignore(v) => v.put(buf)?,
            Message::Debug(v) => v.put(buf)?,
            Message::Unimplemented(v) => v.put(buf)?,
            Message::UserauthBanner(v) => v.put(buf)?,
            Message::GlobalRequest(v) => v.put(buf)?,
            Message::RequestSuccess(v) => v.put(buf)?,
            Message::RequestFailure(v) => v.put(buf)?,
            Message::ChannelOpenFailure(v) => v.put(buf)?,
            Message::ChannelWindowAdjust(v) => v.put(buf)?,
            Message::ChannelExtendedData(v) => v.put(buf)?,
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
            MessageId::ServiceAccept => ServiceAccept::from(buf)?.into(),
            MessageId::UserauthRequest => UserauthRequest::from(buf)?.into(),
            MessageId::UserauthFailure => UserauthFailure::from(buf)?.into(),
            MessageId::UserauthSuccess => UserauthSuccess::from(buf)?.into(),
            MessageId::ChannelOpen => ChannelOpen::from(buf)?.into(),
            MessageId::ChannelOpenConfirmation => ChannelOpenConfirmation::from(buf)?.into(),
            MessageId::ChannelRequest => ChannelRequest::from(buf)?.into(),
            MessageId::ChannelFailure => ChannelFailure::from(buf)?.into(),
            MessageId::ChannelSuccess => ChannelSuccess::from(buf)?.into(),
            MessageId::ChannelData => ChannelData::from(buf)?.into(),
            MessageId::ChannelEof => ChannelEof::from(buf)?.into(),
            MessageId::ChannelClose => ChannelClose::from(buf)?.into(),
            MessageId::Disconnect => Disconnect::from(buf)?.into(),
            MessageId::Ignore => Ignore::from(buf)?.into(),
            MessageId::Debug => Debug::from(buf)?.into(),
            MessageId::Unimplemented => Unimplemented::from(buf)?.into(),
            MessageId::UserauthBanner => UserauthBanner::from(buf)?.into(),
            MessageId::GlobalRequest => GlobalRequest::from(buf)?.into(),
            MessageId::RequestSuccess => RequestSuccess::from(buf)?.into(),
            MessageId::RequestFailure => RequestFailure::from(buf)?.into(),
            MessageId::ChannelOpenFailure=> ChannelOpenFailure::from(buf)?.into(),
            MessageId::ChannelWindowAdjust=>ChannelWindowAdjust::from(buf)?.into(),
            MessageId::ChannelExtendedData =>ChannelExtendedData ::from(buf)?.into(),
        })
    }
}

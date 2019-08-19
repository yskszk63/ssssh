use std::convert::TryFrom;
use std::string::FromUtf8Error;

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut, IntoBuf as _};

use crate::sshbuf::SshBufError;
use crate::transport::codec::CodecError;
pub use channel_close::*;
pub use channel_data::*;
pub use channel_eof::*;
pub use channel_extended_data::*;
pub use channel_failure::*;
pub use channel_open::*;
pub use channel_open_confirmation::*;
pub use channel_open_failure::*;
pub use channel_request::*;
pub use channel_success::*;
pub use channel_window_adjust::*;
pub use debug::*;
pub use disconnect::*;
pub use global_request::*;
pub use id::*;
pub use ignore::*;
pub use kex_ecdh_init::*;
pub use kex_ecdh_reply::*;
pub use kexinit::*;
pub use newkeys::*;
pub use request_failure::*;
pub use request_success::*;
pub use service_accept::*;
pub use service_request::*;
pub use unimplemented::*;
pub use userauth_banner::*;
pub use userauth_failure::*;
pub use userauth_request::*;
pub use userauth_success::*;
pub use userauth_pk_ok::*;
pub use userauth_passwd_changereq::*;
pub use msg60::*;

mod channel_close;
mod channel_data;
mod channel_eof;
mod channel_extended_data;
mod channel_failure;
mod channel_open;
mod channel_open_confirmation;
mod channel_open_failure;
mod channel_request;
mod channel_success;
mod channel_window_adjust;
mod debug;
mod disconnect;
mod global_request;
mod id;
mod ignore;
mod kex_ecdh_init;
mod kex_ecdh_reply;
mod kexinit;
mod newkeys;
mod request_failure;
mod request_success;
mod service_accept;
mod service_request;
mod unimplemented;
mod userauth_banner;
mod userauth_failure;
mod userauth_request;
mod userauth_success;
mod userauth_pk_ok;
mod userauth_passwd_changereq;
mod msg60;

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
    Kexinit(Box<Kexinit>),
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
    UserauthPkOk(UserauthPkOk),
    UserauthPasswdChangereq(UserauthPasswdChangereq),
    Msg60(Msg60),
}

impl Message {
    fn id(&self) -> MessageId {
        match self {
            Self::Kexinit(..) => MessageId::Kexinit,
            Self::KexEcdhInit(..) => MessageId::KexEcdhInit,
            Self::KexEcdhReply(..) => MessageId::KexEcdhReply,
            Self::Newkeys(..) => MessageId::Newkeys,
            Self::ServiceRequest(..) => MessageId::ServiceRequest,
            Self::ServiceAccept(..) => MessageId::ServiceAccept,
            Self::UserauthRequest(..) => MessageId::UserauthRequest,
            Self::UserauthFailure(..) => MessageId::UserauthFailure,
            Self::UserauthSuccess(..) => MessageId::UserauthSuccess,
            Self::ChannelOpen(..) => MessageId::ChannelOpen,
            Self::ChannelOpenConfirmation(..) => MessageId::ChannelOpenConfirmation,
            Self::ChannelRequest(..) => MessageId::ChannelRequest,
            Self::ChannelFailure(..) => MessageId::ChannelFailure,
            Self::ChannelSuccess(..) => MessageId::ChannelSuccess,
            Self::ChannelData(..) => MessageId::ChannelData,
            Self::ChannelEof(..) => MessageId::ChannelEof,
            Self::ChannelClose(..) => MessageId::ChannelClose,
            Self::Disconnect(..) => MessageId::Disconnect,
            Self::Ignore(..) => MessageId::Ignore,
            Self::Debug(..) => MessageId::Debug,
            Self::Unimplemented(..) => MessageId::Unimplemented,
            Self::UserauthBanner(..) => MessageId::UserauthBanner,
            Self::GlobalRequest(..) => MessageId::GlobalRequest,
            Self::RequestSuccess(..) => MessageId::RequestSuccess,
            Self::RequestFailure(..) => MessageId::RequestFailure,
            Self::ChannelOpenFailure(..) => MessageId::ChannelOpenFailure,
            Self::ChannelWindowAdjust(..) => MessageId::ChannelWindowAdjust,
            Self::ChannelExtendedData(..) => MessageId::ChannelExtendedData,
            Self::UserauthPkOk(..) => MessageId::UserauthPkOk,
            Self::UserauthPasswdChangereq(..) => MessageId::UserauthPasswdChangereq,
            Self::Msg60(..) => MessageId::Msg60,
        }
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_u8(self.id().into());
        match self {
            Self::Kexinit(v) => v.put(buf),
            Self::KexEcdhInit(v) => v.put(buf),
            Self::KexEcdhReply(v) => v.put(buf),
            Self::Newkeys(v) => v.put(buf),
            Self::ServiceRequest(v) => v.put(buf),
            Self::ServiceAccept(v) => v.put(buf),
            Self::UserauthRequest(v) => v.put(buf),
            Self::UserauthFailure(v) => v.put(buf),
            Self::UserauthSuccess(v) => v.put(buf),
            Self::ChannelOpen(v) => v.put(buf),
            Self::ChannelOpenConfirmation(v) => v.put(buf),
            Self::ChannelRequest(v) => v.put(buf),
            Self::ChannelFailure(v) => v.put(buf),
            Self::ChannelSuccess(v) => v.put(buf),
            Self::ChannelData(v) => v.put(buf),
            Self::ChannelEof(v) => v.put(buf),
            Self::ChannelClose(v) => v.put(buf),
            Self::Disconnect(v) => v.put(buf),
            Self::Ignore(v) => v.put(buf),
            Self::Debug(v) => v.put(buf),
            Self::Unimplemented(v) => v.put(buf),
            Self::UserauthBanner(v) => v.put(buf),
            Self::GlobalRequest(v) => v.put(buf),
            Self::RequestSuccess(v) => v.put(buf),
            Self::RequestFailure(v) => v.put(buf),
            Self::ChannelOpenFailure(v) => v.put(buf),
            Self::ChannelWindowAdjust(v) => v.put(buf),
            Self::ChannelExtendedData(v) => v.put(buf),
            Self::UserauthPkOk(v) => v.put(buf),
            Self::UserauthPasswdChangereq(v) => v.put(buf),
            Self::Msg60(v) => v.put(buf),
        };
        Ok(())
    }
}

impl TryFrom<Bytes> for Message {
    type Error = MessageError;

    fn try_from(v: Bytes) -> MessageResult<Self> {
        let buf = &mut v.into_buf();
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
            MessageId::ChannelOpenFailure => ChannelOpenFailure::from(buf)?.into(),
            MessageId::ChannelWindowAdjust => ChannelWindowAdjust::from(buf)?.into(),
            MessageId::ChannelExtendedData => ChannelExtendedData::from(buf)?.into(),
            MessageId::UserauthPkOk => UserauthPkOk::from(buf)?.into(),
            MessageId::UserauthPasswdChangereq => UserauthPasswdChangereq::from(buf)?.into(),
            MessageId::Msg60 => Msg60::from(buf)?.into(),
        })
    }
}

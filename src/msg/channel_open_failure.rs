use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub enum ChannelOpenFailureReasonCode {
    AdministrativeProhibited,
    ConnectFailed,
    UnknownChannelType,
    ResourceShortage,
    Unknown(u32),
}

impl From<u32> for ChannelOpenFailureReasonCode {
    fn from(v: u32) -> Self {
        match v {
            1 => Self::AdministrativeProhibited,
            2 => Self::ConnectFailed,
            3 => Self::UnknownChannelType,
            4 => Self::ResourceShortage,
            e => Self::Unknown(e),
        }
    }
}

impl From<ChannelOpenFailureReasonCode> for u32 {
    fn from(v: ChannelOpenFailureReasonCode) -> Self {
        use ChannelOpenFailureReasonCode::*;

        match v {
            AdministrativeProhibited => 1,
            ConnectFailed => 2,
            UnknownChannelType => 3,
            ResourceShortage => 4,
            Unknown(e) => e,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChannelOpenFailure {
    recipient_channel: u32,
    reason_code: ChannelOpenFailureReasonCode,
    description: String,
    language_tag: String,
}

impl ChannelOpenFailure {
    pub fn new(
        recipient_channel: u32,
        reason_code: ChannelOpenFailureReasonCode,
        description: impl Into<String>,
        language_tag: impl Into<String>,
    ) -> Self {
        Self {
            recipient_channel,
            reason_code,
            description: description.into(),
            language_tag: language_tag.into(),
        }
    }

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        let reason_code = buf.get_uint32()?.into();
        let description = buf.get_string()?;
        let language_tag = buf.get_string()?;
        Ok(Self {
            recipient_channel,
            reason_code,
            description,
            language_tag,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) {
        buf.put_uint32(self.recipient_channel);
        buf.put_uint32(self.reason_code.clone().into());
        buf.put_string(&self.description);
        buf.put_string(&self.language_tag);
    }
}

impl From<ChannelOpenFailure> for Message {
    fn from(v: ChannelOpenFailure) -> Self {
        Self::ChannelOpenFailure(v)
    }
}

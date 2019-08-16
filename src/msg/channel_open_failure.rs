use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct ChannelOpenFailure {
    recipient_channel: u32,
    reason_code: u32,
    description: String,
    language_tag: String,
}

impl ChannelOpenFailure {
    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        let reason_code = buf.get_uint32()?;
        let description = buf.get_string()?;
        let language_tag = buf.get_string()?;
        Ok(Self {
            recipient_channel,
            reason_code,
            description,
            language_tag,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_uint32(self.recipient_channel)?;
        buf.put_uint32(self.reason_code)?;
        buf.put_string(&self.description)?;
        buf.put_string(&self.language_tag)?;
        Ok(())
    }
}

impl From<ChannelOpenFailure> for Message {
    fn from(v: ChannelOpenFailure) -> Message {
        Message::ChannelOpenFailure(v)
    }
}

use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct ChannelWindowAdjust {
    recipient_channel: u32,
    bytes_to_add: u32,
}

impl ChannelWindowAdjust {
    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        let bytes_to_add = buf.get_uint32()?;
        Ok(Self { recipient_channel, bytes_to_add })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_uint32(self.recipient_channel)?;
        buf.put_uint32(self.bytes_to_add)?;
        Ok(())
    }
}

impl From<ChannelWindowAdjust> for Message {
    fn from(v: ChannelWindowAdjust) -> Message {
        Message::ChannelWindowAdjust(v)
    }
}

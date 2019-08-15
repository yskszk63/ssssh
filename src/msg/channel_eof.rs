use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct ChannelEof {
    recipient_channel: u32,
}

impl ChannelEof {
    pub fn new(recipient_channel: u32) -> Self {
        Self { recipient_channel }
    }

    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        Ok(Self { recipient_channel, })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_uint32(self.recipient_channel)?;
        Ok(())
    }
}

impl From<ChannelEof> for Message {
    fn from(v: ChannelEof) -> Message {
        Message::ChannelEof(v)
    }
}

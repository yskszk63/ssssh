use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub(crate) struct ChannelClose {
    recipient_channel: u32,
}

impl ChannelClose {
    pub(crate) fn new(recipient_channel: u32) -> Self {
        Self { recipient_channel }
    }

    pub(crate) fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    pub(crate) fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        Ok(Self { recipient_channel })
    }

    pub(crate) fn put(&self, buf: &mut BytesMut) {
        buf.put_uint32(self.recipient_channel);
    }
}

impl From<ChannelClose> for Message {
    fn from(v: ChannelClose) -> Self {
        Self::ChannelClose(v)
    }
}

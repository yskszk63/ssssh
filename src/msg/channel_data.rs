use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub(crate) struct ChannelData {
    recipient_channel: u32,
    data: Bytes,
}

impl ChannelData {
    pub(crate) fn new(recipient_channel: u32, data: Bytes) -> Self {
        Self {
            recipient_channel,
            data,
        }
    }

    pub(crate) fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    pub(crate) fn data(&self) -> &Bytes {
        &self.data
    }

    pub(crate) fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        let data = buf.get_binary_string()?.into();
        Ok(Self {
            recipient_channel,
            data,
        })
    }

    pub(crate) fn put(&self, buf: &mut BytesMut) {
        buf.put_uint32(self.recipient_channel);
        buf.put_binary_string(&self.data);
    }
}

impl From<ChannelData> for Message {
    fn from(v: ChannelData) -> Self {
        Self::ChannelData(v)
    }
}

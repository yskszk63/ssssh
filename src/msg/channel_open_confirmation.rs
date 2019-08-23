use std::io::Cursor;

use bytes::{Buf as _, Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub(crate) struct ChannelOpenConfirmation {
    recipient_channel: u32,
    sender_channel: u32,
    initial_window_size: u32,
    maximum_packet_size: u32,
    data: Bytes,
}

impl ChannelOpenConfirmation {
    pub(crate) fn new(
        recipient_channel: u32,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32,
    ) -> Self {
        let data = Bytes::from("");
        Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            data,
        }
    }

    pub(crate) fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        let sender_channel = buf.get_uint32()?;
        let initial_window_size = buf.get_uint32()?;
        let maximum_packet_size = buf.get_uint32()?;
        let data = buf.take(usize::max_value()).collect();
        Ok(Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            data,
        })
    }

    pub(crate) fn put(&self, buf: &mut BytesMut) {
        buf.put_uint32(self.recipient_channel);
        buf.put_uint32(self.sender_channel);
        buf.put_uint32(self.initial_window_size);
        buf.put_uint32(self.maximum_packet_size);
        buf.extend_from_slice(&self.data);
    }
}

impl From<ChannelOpenConfirmation> for Message {
    fn from(v: ChannelOpenConfirmation) -> Self {
        Self::ChannelOpenConfirmation(v)
    }
}

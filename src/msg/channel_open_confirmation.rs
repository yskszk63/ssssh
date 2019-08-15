use std::io::Cursor;

use bytes::{Bytes, BytesMut, Buf as _, BufMut as _};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct ChannelOpenConfirmation {
    recipient_channel: u32,
    sender_channel: u32,
    initial_window_size: u32,
    maximum_packet_size: u32,
    data: Bytes,
}

impl ChannelOpenConfirmation {
    pub fn new(
        recipient_channel: u32,
        sender_channel: u32,
        initial_window_size: u32,
        maximum_packet_size: u32) -> Self {
        let data = Bytes::from("");
        Self { recipient_channel, sender_channel, initial_window_size, maximum_packet_size, data }
    }

    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        let sender_channel = buf.get_uint32()?;
        let initial_window_size = buf.get_uint32()?;
        let maximum_packet_size = buf.get_uint32()?;
        let data = buf.take(usize::max_value()).collect();
        Ok(Self { recipient_channel, sender_channel, initial_window_size, maximum_packet_size, data, })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_uint32(self.recipient_channel)?;
        buf.put_uint32(self.sender_channel)?;
        buf.put_uint32(self.initial_window_size)?;
        buf.put_uint32(self.maximum_packet_size)?;
        buf.put_slice(&self.data);
        Ok(())
    }
}

impl From<ChannelOpenConfirmation> for Message {
    fn from(v: ChannelOpenConfirmation) -> Message {
        Message::ChannelOpenConfirmation(v)
    }
}

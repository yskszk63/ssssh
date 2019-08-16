use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct ChannelExtendedData {
    recipient_channel: u32,
    data_type_code: u32,
    data: Bytes,
}

impl ChannelExtendedData {
    pub fn new(recipient_channel: u32, data: Bytes) -> Self {
        let data_type_code = 1;
        Self {
            recipient_channel,
            data_type_code,
            data,
        }
    }

    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    pub fn data(&self) -> &Bytes {
        &self.data
    }

    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        let data_type_code = buf.get_uint32()?;
        let data = buf.get_binary_string()?.into();
        Ok(Self {
            recipient_channel,
            data_type_code,
            data,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_uint32(self.recipient_channel)?;
        buf.put_uint32(self.data_type_code)?;
        buf.put_binary_string(&self.data)?;
        Ok(())
    }
}

impl From<ChannelExtendedData> for Message {
    fn from(v: ChannelExtendedData) -> Message {
        Message::ChannelExtendedData(v)
    }
}

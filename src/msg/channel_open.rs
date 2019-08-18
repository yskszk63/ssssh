use std::io::Cursor;

use bytes::{Buf as _, Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub enum ChannelOpenChannelType {
    Session,
    Unknown(String),
}

impl From<String> for ChannelOpenChannelType {
    fn from(v: String) -> Self {
        match v.as_str() {
            "session" => Self::Session,
            e => Self::Unknown(e.to_string()),
        }
    }
}

impl From<ChannelOpenChannelType> for String {
    fn from(v: ChannelOpenChannelType) -> Self {
        use ChannelOpenChannelType::*;
        match v {
            Session => "session".into(),
            Unknown(e) => e,
        }
    }
}

impl AsRef<str> for ChannelOpenChannelType {
    fn as_ref(&self) -> &str {
        use ChannelOpenChannelType::*;
        match self {
            Session => "session",
            Unknown(e) => &e,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChannelOpen {
    channel_type: ChannelOpenChannelType,
    sender_channel: u32,
    initial_window_size: u32,
    maximum_packet_size: u32,
    data: Bytes,
}

impl ChannelOpen {
    pub fn channel_type(&self) -> &ChannelOpenChannelType {
        &self.channel_type
    }

    pub fn sender_channel(&self) -> u32 {
        self.sender_channel
    }

    pub fn initial_window_size(&self) -> u32 {
        self.initial_window_size
    }

    pub fn maximum_packet_size(&self) -> u32 {
        self.maximum_packet_size
    }

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let channel_type = buf.get_string()?.into();
        let sender_channel = buf.get_uint32()?;
        let initial_window_size = buf.get_uint32()?;
        let maximum_packet_size = buf.get_uint32()?;
        let data = buf.take(usize::max_value()).collect();
        Ok(Self {
            channel_type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            data,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_string(self.channel_type.as_ref())?;
        buf.put_uint32(self.sender_channel)?;
        buf.put_uint32(self.initial_window_size)?;
        buf.put_uint32(self.maximum_packet_size)?;
        buf.put_binary_string(&self.data)?;
        Ok(())
    }
}

impl From<ChannelOpen> for Message {
    fn from(v: ChannelOpen) -> Self {
        Self::ChannelOpen(v)
    }
}

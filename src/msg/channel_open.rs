use std::io::Cursor;

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct X11 {
    originator_address: String,
    originator_port: u32,
}

#[derive(Debug, Clone)]
pub struct ForwardedTcpip {
    address: String,
    port: u32,
    originator_address: String,
    originator_port: u32,
}

#[derive(Debug, Clone)]
pub struct DirectTcpip {
    host: String,
    port: u32,
    originator_address: String,
    originator_port: u32,
}

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub enum ChannelOpenChannelType {
    Session,
    X11(X11),
    ForwardedTcpip(ForwardedTcpip),
    DirectTcpip(DirectTcpip),
    Unknown(String, Bytes),
}

impl AsRef<str> for ChannelOpenChannelType {
    fn as_ref(&self) -> &str {
        use ChannelOpenChannelType::*;
        match self {
            Session => "session",
            X11(..) => "x11",
            ForwardedTcpip(..) => "forwarded-tcpip",
            DirectTcpip(..) => "direct-tcpip",
            Unknown(e, ..) => &e,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChannelOpen {
    channel_type: ChannelOpenChannelType,
    sender_channel: u32,
    initial_window_size: u32,
    maximum_packet_size: u32,
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
        let channel_type = buf.get_string()?;
        let sender_channel = buf.get_uint32()?;
        let initial_window_size = buf.get_uint32()?;
        let maximum_packet_size = buf.get_uint32()?;

        let channel_type = match channel_type.as_ref() {
            "session" => {
                ChannelOpenChannelType::Session
            }
            "x11" => {
                ChannelOpenChannelType::X11(X11 {
                    originator_address: buf.get_string()?,
                    originator_port: buf.get_uint32()?,
                })
            }
            "forwarded-tcpip" => {
                ChannelOpenChannelType::ForwardedTcpip(ForwardedTcpip {
                    address: buf.get_string()?,
                    port: buf.get_uint32()?,
                    originator_address: buf.get_string()?,
                    originator_port: buf.get_uint32()?,
                })
            }
            "direct-tcpip" => {
                ChannelOpenChannelType::DirectTcpip(DirectTcpip {
                    host: buf.get_string()?,
                    port: buf.get_uint32()?,
                    originator_address: buf.get_string()?,
                    originator_port: buf.get_uint32()?,
                })
            }
            u => {
                ChannelOpenChannelType::Unknown(u.to_string(), buf.take(usize::max_value()).iter().collect())
            }
        };

        Ok(Self {
            channel_type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_string(self.channel_type.as_ref())?;
        buf.put_uint32(self.sender_channel)?;
        buf.put_uint32(self.initial_window_size)?;
        buf.put_uint32(self.maximum_packet_size)?;
        match &self.channel_type {
            ChannelOpenChannelType::Session => {},
            ChannelOpenChannelType::X11(item) => {
                buf.put_string(&item.originator_address)?;
                buf.put_uint32(item.originator_port)?;
            }
            ChannelOpenChannelType::ForwardedTcpip(item) => {
                buf.put_string(&item.address)?;
                buf.put_uint32(item.port)?;
                buf.put_string(&item.originator_address)?;
                buf.put_uint32(item.originator_port)?;
            }
            ChannelOpenChannelType::DirectTcpip(item) => {
                buf.put_string(&item.host)?;
                buf.put_uint32(item.port)?;
                buf.put_string(&item.originator_address)?;
                buf.put_uint32(item.originator_port)?;
            }
            ChannelOpenChannelType::Unknown(_, data) => {
                buf.put_slice(&data)
            }
        }
        Ok(())
    }
}

impl From<ChannelOpen> for Message {
    fn from(v: ChannelOpen) -> Self {
        Self::ChannelOpen(v)
    }
}

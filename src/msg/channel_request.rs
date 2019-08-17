use std::io::Cursor;

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct ChannelRequest {
    recipient_channel: u32,
    request_type: String,
    want_reply: bool,
    data: Bytes,
}

impl ChannelRequest {
    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    pub fn request_type(&self) -> &str {
        &self.request_type
    }

    /*
    pub fn want_reply(&self) -> bool {
        self.want_reply
    }
    */

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        let request_type = buf.get_string()?;
        let want_reply = buf.get_boolean()?;
        let data = buf.take(usize::max_value()).collect();
        Ok(Self {
            recipient_channel,
            request_type,
            want_reply,
            data,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_uint32(self.recipient_channel)?;
        buf.put_string(&self.request_type)?;
        buf.put_boolean(self.want_reply)?;
        buf.put_slice(&self.data);
        Ok(())
    }
}

impl From<ChannelRequest> for Message {
    fn from(v: ChannelRequest) -> Self {
        Self::ChannelRequest(v)
    }
}

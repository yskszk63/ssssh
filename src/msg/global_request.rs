use std::io::Cursor;

use bytes::{Bytes, BytesMut, Buf as _, BufMut as _};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct GlobalRequest {
    request_type: String,
    want_reply: bool,
    data: Bytes,
}

impl GlobalRequest {
    pub fn request_type(&self) -> &str {
        &self.request_type
    }

    pub fn want_reply(&self) -> bool {
        self.want_reply
    }

    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Self> {
        let request_type = buf.get_string()?;
        let want_reply = buf.get_boolean()?;
        let data = buf.take(usize::max_value()).collect();
        Ok(Self { request_type, want_reply, data })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_string(&self.request_type)?;
        buf.put_boolean(self.want_reply)?;
        buf.put_slice(&self.data);
        Ok(())
    }
}

impl From<GlobalRequest> for Message {
    fn from(v: GlobalRequest) -> Message {
        Message::GlobalRequest(v)
    }
}

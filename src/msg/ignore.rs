use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct Ignore {
    data: Bytes,
}

impl Ignore {
    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Self> {
        let data = buf.get_binary_string()?.into();
        Ok(Self { data })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_binary_string(&self.data)?;
        Ok(())
    }
}

impl From<Ignore> for Message {
    fn from(v: Ignore) -> Message {
        Message::Ignore(v)
    }
}

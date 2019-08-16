use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct Disconnect {
    reason_code: u32,
    description: String,
    language_tag: String,
}

impl Disconnect {
    pub fn new(
        reason_code: u32,
        description: impl Into<String>,
        language_tag: impl Into<String>,
    ) -> Self {
        let description = description.into();
        let language_tag = language_tag.into();
        Disconnect {
            reason_code,
            description,
            language_tag,
        }
    }

    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Self> {
        let reason_code = buf.get_uint32()?;
        let description = buf.get_string()?;
        let language_tag = buf.get_string()?;
        Ok(Self {
            reason_code,
            description,
            language_tag,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_uint32(self.reason_code)?;
        buf.put_string(&self.description)?;
        buf.put_string(&self.language_tag)?;
        Ok(())
    }
}

impl From<Disconnect> for Message {
    fn from(v: Disconnect) -> Message {
        Message::Disconnect(v)
    }
}

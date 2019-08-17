use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct UserauthBanner {
    message: String,
    language_tag: String,
}

impl UserauthBanner {
    pub fn new(message: impl Into<String>, language_tag: impl Into<String>) -> Self {
        let message = message.into();
        let language_tag = language_tag.into();
        Self {
            message,
            language_tag,
        }
    }

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let message = buf.get_string()?;
        let language_tag = buf.get_string()?;
        Ok(Self {
            message,
            language_tag,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_string(&self.message)?;
        buf.put_string(&self.language_tag)?;
        Ok(())
    }
}

impl From<UserauthBanner> for Message {
    fn from(v: UserauthBanner) -> Self {
        Self::UserauthBanner(v)
    }
}

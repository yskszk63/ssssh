use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub(crate) struct Debug {
    always_display: bool,
    message: String,
    language_tag: String,
}

impl Debug {
    pub(crate) fn new(
        always_display: bool,
        message: impl Into<String>,
        language_tag: impl Into<String>,
    ) -> Self {
        let message = message.into();
        let language_tag = language_tag.into();
        Self {
            always_display,
            message,
            language_tag,
        }
    }

    pub(crate) fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let always_display = buf.get_boolean()?;
        let message = buf.get_string()?;
        let language_tag = buf.get_string()?;
        Ok(Self {
            always_display,
            message,
            language_tag,
        })
    }

    pub(crate) fn put(&self, buf: &mut BytesMut) {
        buf.put_boolean(self.always_display);
        buf.put_string(&self.message);
        buf.put_string(&self.language_tag);
    }
}

impl From<Debug> for Message {
    fn from(v: Debug) -> Self {
        Self::Debug(v)
    }
}

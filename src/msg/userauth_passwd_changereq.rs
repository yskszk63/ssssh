use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub(crate) struct UserauthPasswdChangereq {
    prompt: String,
    language_tag: String,
}

impl UserauthPasswdChangereq {
    pub(crate) fn new(prompt: impl Into<String>, language_tag: impl Into<String>) -> Self {
        Self {
            prompt: prompt.into(),
            language_tag: language_tag.into(),
        }
    }

    /*
    pub(crate) fn prompt(&self) -> &str {
        &self.prompt
    }
    */

    /*
    pub(crate) fn language_tag(&self) -> &str {
        &self.language_tag
    }
    */

    pub(crate) fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let prompt = buf.get_string()?;
        let language_tag = buf.get_string()?;
        Ok(Self {
            prompt,
            language_tag,
        })
    }

    pub(crate) fn put(&self, buf: &mut BytesMut) {
        buf.put_string(&self.prompt);
        buf.put_string(&self.language_tag);
    }
}

impl From<UserauthPasswdChangereq> for Message {
    fn from(v: UserauthPasswdChangereq) -> Self {
        Self::UserauthPasswdChangereq(v)
    }
}

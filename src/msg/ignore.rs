use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub(crate) struct Ignore {
    data: Bytes,
}

impl Ignore {
    pub(crate) fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let data = buf.get_binary_string()?.into();
        Ok(Self { data })
    }

    pub(crate) fn put(&self, buf: &mut BytesMut) {
        buf.put_binary_string(&self.data);
    }
}

impl From<Ignore> for Message {
    fn from(v: Ignore) -> Self {
        Self::Ignore(v)
    }
}

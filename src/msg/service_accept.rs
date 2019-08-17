use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct ServiceAccept {
    name: String,
}

impl ServiceAccept {
    pub fn new(name: impl Into<String>) -> Self {
        let name = name.into();
        Self { name }
    }

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let name = buf.get_string()?;
        Ok(Self { name })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_string(&self.name)?;
        Ok(())
    }
}

impl From<ServiceAccept> for Message {
    fn from(v: ServiceAccept) -> Self {
        Self::ServiceAccept(v)
    }
}

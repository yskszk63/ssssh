use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};

#[derive(Debug, Clone)]
pub struct UserauthSuccess;

impl UserauthSuccess {
    pub fn from(_buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        Ok(Self)
    }

    pub fn put(&self, _buf: &mut BytesMut) -> MessageResult<()> {
        Ok(())
    }
}

impl From<UserauthSuccess> for Message {
    fn from(v: UserauthSuccess) -> Self {
        Self::UserauthSuccess(v)
    }
}

use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};

#[derive(Debug, Clone)]
pub(crate) struct UserauthSuccess;

impl UserauthSuccess {
    pub(crate) fn from(_buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        Ok(Self)
    }

    pub(crate) fn put(&self, _buf: &mut BytesMut) {}
}

impl From<UserauthSuccess> for Message {
    fn from(v: UserauthSuccess) -> Self {
        Self::UserauthSuccess(v)
    }
}

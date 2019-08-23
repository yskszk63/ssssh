use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};

#[derive(Debug, Clone)]
pub(crate) struct RequestFailure;

impl RequestFailure {
    pub(crate) fn from(_buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        Ok(Self)
    }

    pub(crate) fn put(&self, _buf: &mut BytesMut) {}
}

impl From<RequestFailure> for Message {
    fn from(v: RequestFailure) -> Self {
        Self::RequestFailure(v)
    }
}

use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};

#[derive(Debug, Clone)]
pub struct RequestFailure;

impl RequestFailure {
    pub fn from(_buf: Cursor<Bytes>) -> MessageResult<Self> {
        Ok(Self)
    }

    pub fn put(&self, _buf: &mut BytesMut) -> MessageResult<()> {
        Ok(())
    }
}

impl From<RequestFailure> for Message {
    fn from(v: RequestFailure) -> Message {
        Message::RequestFailure(v)
    }
}

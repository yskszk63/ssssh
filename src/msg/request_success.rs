use std::io::Cursor;

use bytes::{Buf as _, Bytes, BytesMut};

use super::{Message, MessageResult};

#[derive(Debug, Clone)]
pub(crate) struct RequestSuccess {
    data: Bytes,
}

impl RequestSuccess {
    /*
    pub(crate) fn new() -> Self {
        let data = Bytes::from("");
        Self { data }
    }
    */

    pub(crate) fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let data = buf.to_bytes();
        Ok(Self { data })
    }

    pub(crate) fn put(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.data);
    }
}

impl From<RequestSuccess> for Message {
    fn from(v: RequestSuccess) -> Self {
        Self::RequestSuccess(v)
    }
}

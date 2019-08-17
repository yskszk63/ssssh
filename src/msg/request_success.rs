use std::io::Cursor;

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};

use super::{Message, MessageResult};

#[derive(Debug, Clone)]
pub struct RequestSuccess {
    data: Bytes,
}

impl RequestSuccess {
    /*
    pub fn new() -> Self {
        let data = Bytes::from("");
        Self { data }
    }
    */

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let data = buf.take(usize::max_value()).collect();
        Ok(Self { data })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_slice(&self.data);
        Ok(())
    }
}

impl From<RequestSuccess> for Message {
    fn from(v: RequestSuccess) -> Self {
        Self::RequestSuccess(v)
    }
}

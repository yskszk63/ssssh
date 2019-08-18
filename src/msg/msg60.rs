use std::io::Cursor;

use bytes::{Bytes, BytesMut, Buf as _, BufMut as _};

use super::{Message, MessageResult};

#[derive(Debug, Clone)]
pub struct Msg60(Bytes);

impl Msg60 {
    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        Ok(Self(buf.take(usize::max_value()).iter().collect()))
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_slice(&self.0);
        Ok(())
    }
}

impl From<Msg60> for Message {
    fn from(v: Msg60) -> Self {
        Self::Msg60(v)
    }
}

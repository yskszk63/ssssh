use std::io::Cursor;

use bytes::{Buf as _, Bytes, BytesMut};

use super::{Message, MessageResult};

#[derive(Debug, Clone)]
pub struct Msg60(Bytes);

impl Msg60 {
    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        Ok(Self(buf.take(usize::max_value()).iter().collect()))
    }

    pub fn put(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.0);
    }
}

impl From<Msg60> for Message {
    fn from(v: Msg60) -> Self {
        Self::Msg60(v)
    }
}

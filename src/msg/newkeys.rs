use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};

#[derive(Debug)]
pub struct Newkeys;

impl Newkeys {
    pub fn from(_buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        Ok(Newkeys)
    }
    pub fn put(&self, _buf: &mut BytesMut) {
    }
}

impl From<Newkeys> for Message {
    fn from(v: Newkeys) -> Self {
        Self::Newkeys(v)
    }
}

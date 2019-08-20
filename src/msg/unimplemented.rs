use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct Unimplemented {
    packet_sequence_number: u32,
}

impl Unimplemented {
    /*
    pub fn new(packet_sequence_number: u32) -> Self {
        Self {
            packet_sequence_number,
        }
    }

    pub fn packet_sequence_number(&self) -> u32 {
        self.packet_sequence_number
    }
    */

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let packet_sequence_number = buf.get_uint32()?;
        Ok(Self {
            packet_sequence_number,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) {
        buf.put_uint32(self.packet_sequence_number);
    }
}

impl From<Unimplemented> for Message {
    fn from(v: Unimplemented) -> Self {
        Self::Unimplemented(v)
    }
}

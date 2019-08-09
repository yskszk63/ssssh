use std::io::Cursor;

use bytes::{BufMut as _, Bytes, BytesMut};

use super::{Message, MessageId, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug)]
pub struct KexEdchInit {
    ephemeral_public_key: Vec<u8>,
}

impl KexEdchInit {
    pub fn ephemeral_public_key(&self) -> &[u8] {
        &self.ephemeral_public_key
    }
    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Self> {
        let ephemeral_public_key = buf.get_binary_string()?;
        Ok(Self {
            ephemeral_public_key,
        })
    }
    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_u8(MessageId::KexEcdhInit as u8);
        buf.put_binary_string(&self.ephemeral_public_key)?;
        Ok(())
    }
}

impl From<KexEdchInit> for Message {
    fn from(v: KexEdchInit) -> Message {
        Message::KexEdchInit(v)
    }
}

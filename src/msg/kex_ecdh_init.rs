use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug)]
pub(crate) struct KexEcdhInit {
    ephemeral_public_key: Vec<u8>,
}

impl KexEcdhInit {
    pub(crate) fn ephemeral_public_key(&self) -> &[u8] {
        &self.ephemeral_public_key
    }

    pub(crate) fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let ephemeral_public_key = buf.get_binary_string()?;
        Ok(Self {
            ephemeral_public_key,
        })
    }

    pub(crate) fn put(&self, buf: &mut BytesMut) {
        buf.put_binary_string(&self.ephemeral_public_key);
    }
}

impl From<KexEcdhInit> for Message {
    fn from(v: KexEcdhInit) -> Self {
        Self::KexEcdhInit(v)
    }
}

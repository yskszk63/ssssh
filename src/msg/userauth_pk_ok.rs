use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct UserauthPkOk {
    algorithm: String,
    blob: Bytes,
}

impl UserauthPkOk {
    pub fn new(algorithm: impl Into<String>, blob: impl Into<Bytes>) -> Self {
        Self {
            algorithm: algorithm.into(),
            blob: blob.into(),
        }
    }

    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn blob(&self) -> &Bytes {
        &self.blob
    }

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let algorithm = buf.get_string()?;
        let blob = buf.get_binary_string()?.into();
        Ok(Self { algorithm, blob })
    }

    pub fn put(&self, buf: &mut BytesMut) {
        buf.put_string(&self.algorithm);
        buf.put_binary_string(&self.blob);
    }
}

impl From<UserauthPkOk> for Message {
    fn from(v: UserauthPkOk) -> Self {
        Self::UserauthPkOk(v)
    }
}

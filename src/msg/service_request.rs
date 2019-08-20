use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct ServiceRequest {
    name: String,
}

impl ServiceRequest {
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let name = buf.get_string()?;
        Ok(Self { name })
    }

    pub fn put(&self, buf: &mut BytesMut) {
        buf.put_string(&self.name);
    }
}

impl From<ServiceRequest> for Message {
    fn from(v: ServiceRequest) -> Self {
        Self::ServiceRequest(v)
    }
}

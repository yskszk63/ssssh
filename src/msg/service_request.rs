use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct ServiceRequest {
    name: String,
}

impl ServiceRequest {
    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<ServiceRequest> {
        let name = buf.get_string()?;
        Ok(ServiceRequest { name })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_string(&self.name)?;

        Ok(())
    }
}

impl From<ServiceRequest> for Message {
    fn from(v: ServiceRequest) -> Message {
        Message::ServiceRequest(v)
    }
}

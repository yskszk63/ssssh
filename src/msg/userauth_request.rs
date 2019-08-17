use std::io::Cursor;

use bytes::{Buf as _, Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct UserauthRequest {
    user_name: String,
    service_name: String,
    method_name: String,
    data: Bytes,
}

impl UserauthRequest {
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub fn method_name(&self) -> &str {
        &self.method_name
    }

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let user_name = buf.get_string()?;
        let service_name = buf.get_string()?;
        let method_name = buf.get_string()?;
        let data = buf.take(usize::max_value()).collect();
        Ok(Self {
            user_name,
            service_name,
            method_name,
            data,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_string(&self.user_name)?;
        buf.put_string(&self.service_name)?;
        buf.put_string(&self.method_name)?;
        buf.put_binary_string(&self.data)?;
        Ok(())
    }
}

impl From<UserauthRequest> for Message {
    fn from(v: UserauthRequest) -> Self {
        Self::UserauthRequest(v)
    }
}

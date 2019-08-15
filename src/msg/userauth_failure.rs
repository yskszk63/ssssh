use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct UserauthFailure {
    authentications_that_can_continue: Vec<String>,
    parital_success: bool,
}

impl UserauthFailure {
    pub fn new(
        authentications_that_can_continue: impl IntoIterator<Item=impl Into<String>>,
        parital_success: bool) -> Self {
        let authentications_that_can_continue =
            authentications_that_can_continue.into_iter().map(Into::into).collect();
        Self { authentications_that_can_continue, parital_success }
    }

    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Self> {
        let authentications_that_can_continue = buf.get_name_list()?;
        let parital_success = buf.get_boolean()?;
        Ok(Self { authentications_that_can_continue, parital_success, })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_name_list(&self.authentications_that_can_continue)?;
        buf.put_boolean(self.parital_success)?;
        Ok(())
    }
}

impl From<UserauthFailure> for Message {
    fn from(v: UserauthFailure) -> Message {
        Message::UserauthFailure(v)
    }
}

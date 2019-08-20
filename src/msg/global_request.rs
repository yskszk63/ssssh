use std::io::Cursor;

use bytes::{Buf as _, Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub enum GlobalRequestType {
    TcpipForward(String, u32),
    CancelTcpipForward(String, u32),
    Unknown(String, Bytes),
}

impl AsRef<str> for GlobalRequestType {
    fn as_ref(&self) -> &str {
        match self {
            Self::TcpipForward(..) => "tcpip-forward",
            Self::CancelTcpipForward(..) => "cancel-tcpip-forward",
            Self::Unknown(name, ..) => name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct GlobalRequest {
    request_type: GlobalRequestType,
    want_reply: bool,
}

impl GlobalRequest {
    /*
    pub fn request_type(&self) -> &str {
        &self.request_type
    }

    pub fn want_reply(&self) -> bool {
        self.want_reply
    }
    */

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let request_type = buf.get_string()?;
        let want_reply = buf.get_boolean()?;

        let request_type = match request_type.as_ref() {
            "tcpip-forward" => {
                GlobalRequestType::TcpipForward(buf.get_string()?, buf.get_uint32()?)
            }
            "cancel-tcpip-forward" => {
                GlobalRequestType::CancelTcpipForward(buf.get_string()?, buf.get_uint32()?)
            }
            u => GlobalRequestType::Unknown(
                u.to_string(),
                buf.take(usize::max_value()).iter().collect(),
            ),
        };

        Ok(Self {
            request_type,
            want_reply,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) {
        buf.put_string(self.request_type.as_ref());
        buf.put_boolean(self.want_reply);
        match &self.request_type {
            GlobalRequestType::TcpipForward(addr, port)
            | GlobalRequestType::CancelTcpipForward(addr, port) => {
                buf.put_string(addr);
                buf.put_uint32(*port);
            }
            GlobalRequestType::Unknown(_, data) => {
                buf.extend_from_slice(data);
            }
        }
    }
}

impl From<GlobalRequest> for Message {
    fn from(v: GlobalRequest) -> Self {
        Self::GlobalRequest(v)
    }
}

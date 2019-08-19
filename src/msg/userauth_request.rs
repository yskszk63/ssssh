use std::io::Cursor;

use bytes::{Buf as _, Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct Publickey {
    algorithm: String,
    blob: Bytes,
    signature: Option<Bytes>,
}

impl Publickey {
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }

    pub fn blob(&self) -> &Bytes {
        &self.blob
    }

    pub fn signature(&self) -> &Option<Bytes> {
        &self.signature
    }
}

#[derive(Debug, Clone)]
pub struct Password {
    password: String,
    newpassword: Option<String>,
}

impl Password {
    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn newpassword(&self) -> &Option<String> {
        &self.newpassword
    }
}

#[derive(Debug, Clone)]
pub struct Hostbased {
    algorithm: String,
    client_hostkey: Bytes,
    client_hostname: String,
    user_name: String,
    signature: Bytes,
}

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub enum UserauthRequestMethod {
    None,
    Publickey(Publickey),
    Password(Password),
    Hostbased(Hostbased),
    Unknown(String, Bytes),
}

impl AsRef<str> for UserauthRequestMethod {
    fn as_ref(&self) -> &str {
        match self {
            Self::None => "none",
            Self::Publickey(..) => "publickey",
            Self::Password(..) => "password",
            Self::Hostbased(..) => "hostbased",
            Self::Unknown(n, ..) => n.as_ref(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserauthRequest {
    user_name: String,
    service_name: String,
    method: UserauthRequestMethod,
}

impl UserauthRequest {
    pub fn user_name(&self) -> &str {
        &self.user_name
    }

    pub fn service_name(&self) -> &str {
        &self.service_name
    }

    pub fn method(&self) -> &UserauthRequestMethod {
        &self.method
    }

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let user_name = buf.get_string()?;
        let service_name = buf.get_string()?;
        let method_name = buf.get_string()?;
        let method = match method_name.as_ref() {
            "none" => {
                UserauthRequestMethod::None
            }
            "publickey" => {
                let has_signature = buf.get_boolean()?;
                UserauthRequestMethod::Publickey(Publickey {
                    algorithm: buf.get_string()?,
                    blob: buf.get_binary_string()?.into(),
                    signature: if has_signature {
                        Some(buf.get_binary_string()?.into())
                    } else {
                        None
                    }
                })
            }
            "password" => {
                let has_newpassword = buf.get_boolean()?;
                UserauthRequestMethod::Password(Password {
                    password: buf.get_string()?,
                    newpassword: if has_newpassword {
                        Some(buf.get_string()?)
                    } else {
                        None
                    }
                })
            }
            "hostbased" => {
                UserauthRequestMethod::Hostbased(Hostbased {
                    algorithm: buf.get_string()?,
                    client_hostkey: buf.get_binary_string()?.into(),
                    client_hostname: buf.get_string()?,
                    user_name: buf.get_string()?,
                    signature: buf.get_binary_string()?.into(),
                })
            }
            u => {
                UserauthRequestMethod::Unknown(u.to_string(), buf.take(usize::max_value()).iter().collect())
            }
        };

        Ok(Self {
            user_name,
            service_name,
            method,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) {
        buf.put_string(&self.user_name);
        buf.put_string(&self.service_name);
        buf.put_string(&self.method.as_ref());
        match &self.method {
            UserauthRequestMethod::None => {}
            UserauthRequestMethod::Publickey(item) => {
                buf.put_boolean(item.signature.is_some());
                buf.put_string(item.algorithm.as_ref());
                buf.put_binary_string(&item.blob);
                if let Some(e) = &item.signature {
                    buf.put_binary_string(e);
                }
            }
            UserauthRequestMethod::Password(item) => {
                buf.put_boolean(item.newpassword.is_some());
                buf.put_string(item.password.as_ref());
                if let Some(e) = &item.newpassword {
                    buf.put_string(e);
                }
            }
            UserauthRequestMethod::Hostbased(item) => {
                buf.put_string(&item.algorithm);
                buf.put_binary_string(&item.client_hostkey);
                buf.put_string(&item.client_hostname);
                buf.put_string(&item.user_name);
                buf.put_binary_string(&item.signature);
            }
            UserauthRequestMethod::Unknown(_, data) => {
                buf.extend_from_slice(&data);
            }
        }
    }
}

impl From<UserauthRequest> for Message {
    fn from(v: UserauthRequest) -> Self {
        Self::UserauthRequest(v)
    }
}

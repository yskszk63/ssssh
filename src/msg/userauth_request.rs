use getset::Getters;

use super::*;
use crate::key::{PublicKey as Pk, Signature};

#[derive(Debug, Getters)]
pub(crate) struct Publickey {
    #[get = "pub(crate)"]
    algorithm: String,

    #[get = "pub(crate)"]
    blob: Pk,

    #[get = "pub(crate)"]
    signature: Option<Signature>,
}

impl Pack for Publickey {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.signature.is_some().pack(buf);
        self.algorithm.pack(buf);
        self.blob.pack(buf);
        if let Some(sig) = &self.signature {
            sig.pack(buf);
        }
    }
}

impl Unpack for Publickey {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let has_signature = bool::unpack(buf)?;
        let algorithm = Unpack::unpack(buf)?;
        let blob = Unpack::unpack(buf)?;
        let signature = if has_signature {
            Some(Unpack::unpack(buf)?)
        } else {
            None
        };

        Ok(Self {
            algorithm,
            blob,
            signature,
        })
    }
}

#[derive(Debug, Getters)]
pub(crate) struct Password {
    #[get = "pub(crate)"]
    password: String,

    #[get = "pub(crate)"]
    newpassword: Option<String>,
}

impl Pack for Password {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.newpassword.is_some().pack(buf);
        self.password.pack(buf);
        if let Some(newpassword) = &self.newpassword {
            newpassword.pack(buf);
        }
    }
}

impl Unpack for Password {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let has_newpassword = bool::unpack(buf)?;
        let password = Unpack::unpack(buf)?;
        let newpassword = if has_newpassword {
            Some(Unpack::unpack(buf)?)
        } else {
            None
        };

        Ok(Self {
            password,
            newpassword,
        })
    }
}

#[derive(Debug, Getters)]
pub(crate) struct Hostbased {
    #[get = "pub(crate)"]
    algorithm: String,

    #[get = "pub(crate)"]
    client_hostkey: Pk,

    #[get = "pub(crate)"]
    client_hostname: String,

    #[get = "pub(crate)"]
    user_name: String,

    #[get = "pub(crate)"]
    signature: Signature,
}

impl Pack for Hostbased {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.algorithm.pack(buf);
        self.client_hostkey.pack(buf);
        self.client_hostname.pack(buf);
        self.user_name.pack(buf);
        self.signature.pack(buf);
    }
}

impl Unpack for Hostbased {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let algorithm = Unpack::unpack(buf)?;
        let client_hostkey = Unpack::unpack(buf)?;
        let client_hostname = Unpack::unpack(buf)?;
        let user_name = Unpack::unpack(buf)?;
        let signature = Unpack::unpack(buf)?;

        Ok(Self {
            algorithm,
            client_hostkey,
            client_hostname,
            user_name,
            signature,
        })
    }
}

#[derive(Debug)]
pub(crate) enum Method {
    None,
    Publickey(Publickey),
    Password(Password),
    Hostbased(Hostbased),
    Unknown(String, Bytes),
}

impl Pack for Method {
    fn pack<P: Put>(&self, buf: &mut P) {
        match self {
            Self::None => "none".to_string().pack(buf),
            Self::Publickey(item) => {
                "publickey".pack(buf);
                item.pack(buf)
            }
            Self::Password(item) => {
                "password".pack(buf);
                item.pack(buf)
            }
            Self::Hostbased(item) => {
                "hostbased".pack(buf);
                item.pack(buf)
            }
            Self::Unknown(name, item) => {
                name.pack(buf);
                buf.put(item);
            }
        }
    }
}

impl Unpack for Method {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let method = String::unpack(buf)?;
        Ok(match &*method {
            "none" => Self::None,
            "publickey" => Self::Publickey(Unpack::unpack(buf)?),
            "password" => Self::Password(Unpack::unpack(buf)?),
            "hostbased" => Self::Hostbased(Unpack::unpack(buf)?),
            x => Self::Unknown(x.into(), buf.to_bytes()),
        })
    }
}

#[derive(Debug, Getters)]
pub(crate) struct UserauthRequest {
    #[get = "pub(crate)"]
    user_name: String,
    #[get = "pub(crate)"]
    service_name: String,
    #[get = "pub(crate)"]
    method: Method,
}

impl MsgItem for UserauthRequest {
    const ID: u8 = 50;
}

impl Pack for UserauthRequest {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.user_name.pack(buf);
        self.service_name.pack(buf);
        self.method.pack(buf);
    }
}

impl Unpack for UserauthRequest {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let user_name = Unpack::unpack(buf)?;
        let service_name = Unpack::unpack(buf)?;
        let method = Unpack::unpack(buf)?;

        Ok(Self {
            user_name,
            service_name,
            method,
        })
    }
}

impl From<UserauthRequest> for Msg {
    fn from(v: UserauthRequest) -> Self {
        Self::UserauthRequest(v)
    }
}

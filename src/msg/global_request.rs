use getset::Getters;

use super::*;

#[derive(Debug, Getters)]
pub(crate) struct TcpipForward {
    address_to_bind: String,
    port_number_to_bind: u32,
}

impl Pack for TcpipForward {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.address_to_bind.pack(buf);
        self.port_number_to_bind.pack(buf);
    }
}

impl Unpack for TcpipForward {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let address_to_bind = Unpack::unpack(buf)?;
        let port_number_to_bind = Unpack::unpack(buf)?;

        Ok(Self {
            address_to_bind,
            port_number_to_bind,
        })
    }
}

#[derive(Debug, Getters)]
pub(crate) struct CancelTcpipForward {
    address_to_bind: String,
    port_number_to_bind: u32,
}

impl Pack for CancelTcpipForward {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.address_to_bind.pack(buf);
        self.port_number_to_bind.pack(buf);
    }
}

impl Unpack for CancelTcpipForward {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let address_to_bind = Unpack::unpack(buf)?;
        let port_number_to_bind = Unpack::unpack(buf)?;

        Ok(Self {
            address_to_bind,
            port_number_to_bind,
        })
    }
}

#[derive(Debug)]
pub(crate) enum Type {
    TcpipForward(TcpipForward),
    CancelTcpipForward(CancelTcpipForward),
    Unknown(String, Bytes),
}

#[derive(Debug, Getters)]
pub(crate) struct GlobalRequest {
    #[get = "pub(crate)"]
    want_reply: bool,

    #[get = "pub(crate)"]
    typ: Type,
}

impl MsgItem for GlobalRequest {
    const ID: u8 = 80;
}

impl Pack for GlobalRequest {
    fn pack<P: Put>(&self, buf: &mut P) {
        match &self.typ {
            Type::TcpipForward(..) => "tcpip-forward",
            Type::CancelTcpipForward(..) => "cancel-tcpip-forward",
            Type::Unknown(t, ..) => &*t,
        }
        .pack(buf);

        self.want_reply.pack(buf);

        match &self.typ {
            Type::TcpipForward(x) => x.pack(buf),
            Type::CancelTcpipForward(x) => x.pack(buf),
            Type::Unknown(_, x) => buf.put(&x),
        }
    }
}

impl Unpack for GlobalRequest {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let typ = String::unpack(buf)?;
        let want_reply = Unpack::unpack(buf)?;
        let typ = match &*typ {
            "tcpip-forward" => Type::TcpipForward(Unpack::unpack(buf)?),
            "cancel-tcpip-forward" => Type::CancelTcpipForward(Unpack::unpack(buf)?),
            x => Type::Unknown(x.to_string(), buf.to_bytes()),
        };

        Ok(Self { want_reply, typ })
    }
}

impl From<GlobalRequest> for Msg {
    fn from(v: GlobalRequest) -> Self {
        Self::GlobalRequest(v)
    }
}

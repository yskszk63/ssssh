use getset::Getters;

use super::*;

#[derive(Debug, Getters)]
pub(crate) struct X11 {
    #[get = "pub(crate)"]
    originator_address: String,

    #[get = "pub(crate)"]
    originator_port: u32,
}

impl Pack for X11 {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.originator_address.pack(buf);
        self.originator_port.pack(buf);
    }
}

impl Unpack for X11 {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let originator_address = Unpack::unpack(buf)?;
        let originator_port = Unpack::unpack(buf)?;
        Ok(Self {
            originator_address,
            originator_port,
        })
    }
}

#[derive(Debug, Getters)]
pub(crate) struct ForwardedTcpip {
    #[get = "pub(crate)"]
    address: String,

    #[get = "pub(crate)"]
    port: u32,

    #[get = "pub(crate)"]
    originator_address: String,

    #[get = "pub(crate)"]
    originator_port: u32,
}

impl Pack for ForwardedTcpip {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.address.pack(buf);
        self.port.pack(buf);
        self.originator_address.pack(buf);
        self.originator_port.pack(buf);
    }
}

impl Unpack for ForwardedTcpip {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let address = Unpack::unpack(buf)?;
        let port = Unpack::unpack(buf)?;
        let originator_address = Unpack::unpack(buf)?;
        let originator_port = Unpack::unpack(buf)?;
        Ok(Self {
            address,
            port,
            originator_address,
            originator_port,
        })
    }
}

#[derive(Debug, Getters)]
pub(crate) struct DirectTcpip {
    #[get = "pub(crate)"]
    host: String,

    #[get = "pub(crate)"]
    port: u32,

    #[get = "pub(crate)"]
    originator_address: String,

    #[get = "pub(crate)"]
    originator_port: u32,
}

impl Pack for DirectTcpip {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.host.pack(buf);
        self.port.pack(buf);
        self.originator_address.pack(buf);
        self.originator_port.pack(buf);
    }
}

impl Unpack for DirectTcpip {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let host = Unpack::unpack(buf)?;
        let port = Unpack::unpack(buf)?;
        let originator_address = Unpack::unpack(buf)?;
        let originator_port = Unpack::unpack(buf)?;
        Ok(Self {
            host,
            port,
            originator_address,
            originator_port,
        })
    }
}

#[derive(Debug)]
pub(crate) enum Type {
    Session(()),
    X11(X11),
    ForwardedTcpip(ForwardedTcpip),
    DirectTcpip(DirectTcpip),
    Unknown(String, Bytes),
}

#[derive(Debug, Getters)]
pub(crate) struct ChannelOpen {
    #[get = "pub(crate)"]
    sender_channel: u32,

    #[get = "pub(crate)"]
    initial_window_size: u32,

    #[get = "pub(crate)"]
    maximum_packet_size: u32,

    #[get = "pub(crate)"]
    typ: Type,
}

impl MsgItem for ChannelOpen {
    const ID: u8 = 90;
}

impl Pack for ChannelOpen {
    fn pack<P: Put>(&self, buf: &mut P) {
        let typ = match self.typ() {
            Type::Session(()) => "session",
            Type::X11(..) => "x11",
            Type::ForwardedTcpip(..) => "forwarded-tcpip",
            Type::DirectTcpip(..) => "direct-tcpip",
            Type::Unknown(name, _) => name.as_str(),
        };

        typ.pack(buf);
        self.sender_channel.pack(buf);
        self.initial_window_size.pack(buf);
        self.maximum_packet_size.pack(buf);

        match self.typ() {
            Type::Session(..) => {}
            Type::X11(item) => item.pack(buf),
            Type::ForwardedTcpip(item) => item.pack(buf),
            Type::DirectTcpip(item) => item.pack(buf),
            Type::Unknown(_, item) => {
                buf.put(&item);
            }
        }
    }
}

impl Unpack for ChannelOpen {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let typ = String::unpack(buf)?;
        let sender_channel = Unpack::unpack(buf)?;
        let initial_window_size = Unpack::unpack(buf)?;
        let maximum_packet_size = Unpack::unpack(buf)?;
        let typ = match &*typ {
            "session" => Type::Session(()),
            "x11" => Type::X11(Unpack::unpack(buf)?),
            "forwarded-tcpip" => Type::ForwardedTcpip(Unpack::unpack(buf)?),
            "direct-tcpip" => Type::DirectTcpip(Unpack::unpack(buf)?),
            v => Type::Unknown(v.to_string(), buf.to_bytes()),
        };

        Ok(Self {
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            typ,
        })
    }
}

impl From<ChannelOpen> for Msg {
    fn from(v: ChannelOpen) -> Self {
        Self::ChannelOpen(v)
    }
}

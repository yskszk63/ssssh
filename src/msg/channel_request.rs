use derive_new::new;
use getset::Getters;

use super::*;

#[derive(Debug, Getters, new)]
pub(crate) struct PtyReq {
    #[get = "pub(crate)"]
    term: String,
    #[get = "pub(crate)"]
    width: u32,
    #[get = "pub(crate)"]
    height: u32,
    #[get = "pub(crate)"]
    width_px: u32,
    #[get = "pub(crate)"]
    height_px: u32,
    #[get = "pub(crate)"]
    modes: Bytes,
}

impl Pack for PtyReq {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.term.pack(buf);
        self.width.pack(buf);
        self.height.pack(buf);
        self.width_px.pack(buf);
        self.height_px.pack(buf);
        self.modes.pack(buf);
    }
}

impl Unpack for PtyReq {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let term = Unpack::unpack(buf)?;
        let width = Unpack::unpack(buf)?;
        let height = Unpack::unpack(buf)?;
        let width_px = Unpack::unpack(buf)?;
        let height_px = Unpack::unpack(buf)?;
        let modes = Unpack::unpack(buf)?;

        Ok(Self {
            term,
            width,
            height,
            width_px,
            height_px,
            modes,
        })
    }
}

#[derive(Debug, Getters, new)]
pub(crate) struct X11Req {
    #[get = "pub(crate)"]
    single_connection: bool,
    #[get = "pub(crate)"]
    x11_auth_protocol: String,
    #[get = "pub(crate)"]
    x11_auth_cookie: Bytes,
    #[get = "pub(crate)"]
    x11_screen_number: u32,
}

impl Pack for X11Req {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.single_connection.pack(buf);
        self.x11_auth_protocol.pack(buf);
        self.x11_auth_cookie.pack(buf);
        self.x11_screen_number.pack(buf);
    }
}

impl Unpack for X11Req {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let single_connection = Unpack::unpack(buf)?;
        let x11_auth_protocol = Unpack::unpack(buf)?;
        let x11_auth_cookie = Unpack::unpack(buf)?;
        let x11_screen_number = Unpack::unpack(buf)?;

        Ok(Self {
            single_connection,
            x11_auth_protocol,
            x11_auth_cookie,
            x11_screen_number,
        })
    }
}

#[derive(Debug, Getters, new)]
pub(crate) struct Env {
    #[get = "pub(crate)"]
    name: String,
    #[get = "pub(crate)"]
    value: String,
}

impl Pack for Env {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.name.pack(buf);
        self.value.pack(buf);
    }
}

impl Unpack for Env {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let name = Unpack::unpack(buf)?;
        let value = Unpack::unpack(buf)?;

        Ok(Self { name, value })
    }
}

#[derive(Debug, Getters, new)]
pub(crate) struct WindowChange {
    #[get = "pub(crate)"]
    width: u32,
    #[get = "pub(crate)"]
    height: u32,
    #[get = "pub(crate)"]
    width_px: u32,
    #[get = "pub(crate)"]
    height_px: u32,
}

impl Pack for WindowChange {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.width.pack(buf);
        self.height.pack(buf);
        self.width_px.pack(buf);
        self.height_px.pack(buf);
    }
}

impl Unpack for WindowChange {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let width = Unpack::unpack(buf)?;
        let height = Unpack::unpack(buf)?;
        let width_px = Unpack::unpack(buf)?;
        let height_px = Unpack::unpack(buf)?;

        Ok(Self {
            width,
            height,
            width_px,
            height_px,
        })
    }
}

#[derive(Debug, Getters, new)]
pub(crate) struct ExitSignal {
    #[get = "pub(crate)"]
    name: String,
    #[get = "pub(crate)"]
    core_dump: bool,
    #[get = "pub(crate)"]
    error_message: String,
    #[get = "pub(crate)"]
    language_tag: String,
}

impl Pack for ExitSignal {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.name.pack(buf);
        self.core_dump.pack(buf);
        self.error_message.pack(buf);
        self.language_tag.pack(buf);
    }
}

impl Unpack for ExitSignal {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let name = Unpack::unpack(buf)?;
        let core_dump = Unpack::unpack(buf)?;
        let error_message = Unpack::unpack(buf)?;
        let language_tag = Unpack::unpack(buf)?;

        Ok(Self {
            name,
            core_dump,
            error_message,
            language_tag,
        })
    }
}

#[derive(Debug)]
pub(crate) enum Type {
    PtyReq(PtyReq),
    X11Req(X11Req),
    Env(Env),
    Shell(()),
    Exec(Bytes),
    Subsystem(String),
    WindowChange(WindowChange),
    XonXoff(bool),
    Signal(String),
    ExitStatus(u32),
    ExitSignal(ExitSignal),
    Unknown(String, Bytes),
}

#[derive(Debug, Getters, new)]
pub(crate) struct ChannelRequest {
    #[get = "pub(crate)"]
    recipient_channel: u32,

    #[get = "pub(crate)"]
    want_reply: bool,

    #[get = "pub(crate)"]
    typ: Type,
}

impl MsgItem for ChannelRequest {
    const ID: u8 = 98;
}

impl Pack for ChannelRequest {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.recipient_channel.pack(buf);
        match &self.typ {
            Type::PtyReq(..) => "pty-req",
            Type::X11Req(..) => "x11-req",
            Type::Env(..) => "env",
            Type::Shell(..) => "shell",
            Type::Exec(..) => "exec",
            Type::Subsystem(..) => "subsystem",
            Type::WindowChange(..) => "window-change",
            Type::XonXoff(..) => "xon-xoff",
            Type::Signal(..) => "signal",
            Type::ExitStatus(..) => "exit-status",
            Type::ExitSignal(..) => "exit-signal",
            Type::Unknown(name, ..) => &*name,
        }
        .pack(buf);
        self.want_reply.pack(buf);

        match &self.typ {
            Type::PtyReq(item) => item.pack(buf),
            Type::X11Req(item) => item.pack(buf),
            Type::Env(item) => item.pack(buf),
            Type::Shell(..) => {}
            Type::Exec(item) => item.pack(buf),
            Type::Subsystem(item) => item.pack(buf),
            Type::WindowChange(item) => item.pack(buf),
            Type::XonXoff(item) => item.pack(buf),
            Type::Signal(item) => item.pack(buf),
            Type::ExitStatus(item) => item.pack(buf),
            Type::ExitSignal(item) => item.pack(buf),
            Type::Unknown(_, data) => buf.put(&data),
        }
    }
}

impl Unpack for ChannelRequest {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let recipient_channel = Unpack::unpack(buf)?;
        let typ = String::unpack(buf)?;
        let want_reply = Unpack::unpack(buf)?;

        let typ = match &*typ {
            "pty-req" => Type::PtyReq(Unpack::unpack(buf)?),
            "x11-req" => Type::X11Req(Unpack::unpack(buf)?),
            "env" => Type::Env(Unpack::unpack(buf)?),
            "shell" => Type::Shell(()),
            "exec" => Type::Exec(Unpack::unpack(buf)?),
            "subsystem" => Type::Subsystem(Unpack::unpack(buf)?),
            "window-change" => Type::WindowChange(Unpack::unpack(buf)?),
            "xon-xoff" => Type::XonXoff(Unpack::unpack(buf)?),
            "signal" => Type::Signal(Unpack::unpack(buf)?),
            "exit-status" => Type::ExitStatus(Unpack::unpack(buf)?),
            "exit-signal" => Type::ExitSignal(Unpack::unpack(buf)?),
            x => Type::Unknown(x.into(), buf.copy_to_bytes(buf.remaining())),
        };

        Ok(Self {
            recipient_channel,
            want_reply,
            typ,
        })
    }
}

impl From<ChannelRequest> for Msg {
    fn from(v: ChannelRequest) -> Self {
        Self::ChannelRequest(v)
    }
}

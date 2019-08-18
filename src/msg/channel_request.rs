use std::io::Cursor;

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Clone)]
pub struct PtyReq {
    term_name: String,
    terminal_width: u32,
    terminal_height: u32,
    terminal_width_px: u32,
    terminal_height_px: u32,
    terminal_modes: Bytes,
}

impl PtyReq {
    pub fn term_name(&self) -> &str {
        &self.term_name
    }

    pub fn terminal_width(&self) -> u32 {
        self.terminal_width
    }

    pub fn terminal_height(&self) -> u32 {
        self.terminal_height
    }

    pub fn terminal_width_px(&self) -> u32 {
        self.terminal_width_px
    }

    pub fn terminal_height_px(&self) -> u32 {
        self.terminal_height_px
    }

    pub fn terminal_modes(&self) -> &Bytes {
        &self.terminal_modes
    }
}

#[derive(Debug, Clone)]
pub struct X11Req {
    signle_connection: bool,
    x11_authentication_protocol: String,
    x11_authentication_cookie: Bytes,
    x11_screen_number: u32,
}

impl X11Req {
    pub fn signle_connection(&self) -> bool {
        self.signle_connection
    }

    pub fn x11_authentication_protocol(&self) -> &str {
        &self.x11_authentication_protocol
    }

    pub fn x11_authentication_cookie(&self) -> &Bytes {
        &self.x11_authentication_cookie
    }

    pub fn x11_screen_number(&self) -> u32 {
        self.x11_screen_number
    }
}

#[derive(Debug, Clone)]
pub struct WindowChange {
    terminal_width: u32,
    terminal_height: u32,
    terminal_width_px: u32,
    terminal_height_px: u32,
}

impl WindowChange {
    pub fn terminal_width(&self) -> u32 {
        self.terminal_width
    }

    pub fn terminal_height(&self) -> u32 {
        self.terminal_height
    }

    pub fn terminal_width_px(&self) -> u32 {
        self.terminal_width_px
    }

    pub fn terminal_height_px(&self) -> u32 {
        self.terminal_height_px
    }
}

#[derive(Debug, Clone)]
pub enum Signal {
    Abrt,
    Alrm,
    Fpe,
    Hup,
    Ill,
    Int,
    Kill,
    Pipe,
    Quit,
    Segv,
    Term,
    Usr1,
    Usr2,
    Unknown(String),
}

impl From<String> for Signal {
    fn from(v: String) -> Self {
        match v.as_ref() {
            "ABRT" => Self::Abrt,
            "ALRM" => Self::Alrm,
            "FPE" => Self::Fpe,
            "HUP" => Self::Hup,
            "ILL" => Self::Ill,
            "INT" => Self::Int,
            "KILL" => Self::Kill,
            "PIPE" => Self::Pipe,
            "QUIT" => Self::Quit,
            "SEGV" => Self::Segv,
            "TERM" => Self::Term,
            "USR1" => Self::Usr1,
            "USR2" => Self::Usr2,
            sig => Self::Unknown(sig.to_string()),
        }
    }
}

impl AsRef<str> for Signal {
    fn as_ref(&self) -> &str {
        match self {
            Self::Abrt => "ABRT",
            Self::Alrm => "ALRM",
            Self::Fpe => "FPE",
            Self::Hup => "HUP",
            Self::Ill => "ILL",
            Self::Int => "INT",
            Self::Kill => "KILL",
            Self::Pipe => "PIPE",
            Self::Quit => "QUIT",
            Self::Segv => "SEGV",
            Self::Term => "TERM",
            Self::Usr1 => "USR1",
            Self::Usr2 => "USR2",
            Self::Unknown(v) => &v,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExitSignal {
    signal: Signal,
    coredumped: bool,
    error_message: String,
    language_tag: String,
}

impl ExitSignal {
    pub fn signal(&self) -> &Signal {
        &self.signal
    }

    pub fn coredumped(&self) -> bool {
        self.coredumped
    }

    pub fn error_message(&self) -> &str {
        &self.error_message
    }

    pub fn language_tag(&self) -> &str {
        &self.language_tag
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub enum ChannelRequestType {
    PtyReq(PtyReq),
    X11Req(X11Req),
    Env(String, String),
    Shell,
    Exec(String),
    Subsystem(String),
    WindowChange(WindowChange),
    XonXoff(bool),
    Signal(Signal),
    ExitStatus(u32),
    ExitSignal(ExitSignal),
    Unknown {
        name: String,
        data: Bytes,
    }
}

impl ChannelRequestType {
    fn name(&self) -> &str {
        use ChannelRequestType::*;

        match self {
            PtyReq(..) => "pty-req",
            X11Req(..) => "x11-req",
            Env(..) => "env",
            Shell => "shell",
            Exec(..) => "exec",
            Subsystem(..) => "subsystem",
            WindowChange(..) => "window-change",
            XonXoff(..) => "xon-xoff",
            Signal(..) => "signal",
            ExitStatus(..) => "exit-status",
            ExitSignal(..) => "exit-signal",
            Unknown { name, .. } => &name,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ChannelRequest {
    recipient_channel: u32,
    request_type: ChannelRequestType,
    want_reply: bool,
}

impl ChannelRequest {
    pub fn new_exit_status(recipient_channel: u32, exit_code: u32) -> Self {
        Self {
            recipient_channel,
            request_type: ChannelRequestType::ExitStatus(exit_code),
            want_reply: false,
        }
    }

    pub fn new_exit_signal(
        recipient_channel: u32, signal: Signal,
        coredumped: bool, error_message: impl Into<String>,
        language_tag: impl Into<String>) -> Self {

        Self {
            recipient_channel,
            request_type: ChannelRequestType::ExitSignal(ExitSignal {
                signal,
                coredumped,
                error_message: error_message.into(),
                language_tag: language_tag.into(),
            }),
            want_reply: false,
        }
    }

    pub fn recipient_channel(&self) -> u32 {
        self.recipient_channel
    }

    pub fn request_type(&self) -> &ChannelRequestType {
        &self.request_type
    }

    pub fn want_reply(&self) -> bool {
        self.want_reply
    }

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let recipient_channel = buf.get_uint32()?;
        let request_type = buf.get_string()?;
        let want_reply = buf.get_boolean()?;

        let request_type = match request_type.as_ref() {
            "pty-req" => {
                ChannelRequestType::PtyReq(PtyReq {
                    term_name : buf.get_string()?,
                    terminal_width : buf.get_uint32()?,
                    terminal_height : buf.get_uint32()?,
                    terminal_width_px : buf.get_uint32()?,
                    terminal_height_px : buf.get_uint32()?,
                    terminal_modes : buf.get_binary_string()?.into(),
                })
            }
            "x11-req" => {
                ChannelRequestType::X11Req(X11Req {
                    signle_connection: buf.get_boolean()?,
                    x11_authentication_protocol: buf.get_string()?,
                    x11_authentication_cookie: buf.get_string()?.into(),
                    x11_screen_number: buf.get_uint32()?,
                })
            }
            "env" => {
                ChannelRequestType::Env(buf.get_string()?, buf.get_string()?)
            }
            "shell" => {
                ChannelRequestType::Shell
            }
            "exec" => {
                ChannelRequestType::Exec(buf.get_string()?)
            }
            "subsystem" => {
                ChannelRequestType::Subsystem(buf.get_string()?)
            }
            "window-change" => {
                ChannelRequestType::WindowChange(WindowChange {
                    terminal_width : buf.get_uint32()?,
                    terminal_height : buf.get_uint32()?,
                    terminal_width_px : buf.get_uint32()?,
                    terminal_height_px : buf.get_uint32()?,
                })
            }
            "xon-xoff" => {
                ChannelRequestType::XonXoff(buf.get_boolean()?)
            }
            "signal" => {
                ChannelRequestType::Signal(buf.get_string()?.into())
            }
            "exit-status" => {
                ChannelRequestType::ExitStatus(buf.get_uint32()?)
            }
            "exit-signal" => {
                ChannelRequestType::ExitSignal(ExitSignal {
                    signal: buf.get_string()?.into(),
                    coredumped: buf.get_boolean()?,
                    error_message: buf.get_string()?,
                    language_tag: buf.get_string()?,
                })
            }
            name => {
                ChannelRequestType::Unknown {
                    name: name.to_string(),
                    data: buf.take(usize::max_value()).iter().collect()
                }
            }
        };

        Ok(Self {
            recipient_channel,
            request_type,
            want_reply,
        })
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        use ChannelRequestType::*;

        buf.put_uint32(self.recipient_channel)?;
        buf.put_string(&self.request_type.name())?;
        buf.put_boolean(self.want_reply)?;
        match &self.request_type {
            PtyReq(v) => {
                buf.put_string(v.term_name())?;
                buf.put_uint32(v.terminal_width())?;
                buf.put_uint32(v.terminal_height())?;
                buf.put_uint32(v.terminal_width_px())?;
                buf.put_uint32(v.terminal_height_px())?;
                buf.put_binary_string(v.terminal_modes())?;
            }
            X11Req(v) => {
                buf.put_boolean(v.signle_connection())?;
                buf.put_string(v.x11_authentication_protocol())?;
                buf.put_binary_string(v.x11_authentication_cookie())?;
                buf.put_uint32(v.x11_screen_number())?;
            }
            Env(k, v) => {
                buf.put_string(k)?;
                buf.put_string(v)?;
            }
            Shell => {}
            Exec(v) | Subsystem(v) => {
                buf.put_string(v)?;
            }
            WindowChange(v) => {
                buf.put_uint32(v.terminal_width())?;
                buf.put_uint32(v.terminal_height())?;
                buf.put_uint32(v.terminal_width_px())?;
                buf.put_uint32(v.terminal_height_px())?;
            }
            XonXoff(v) => {
                buf.put_boolean(*v)?;
            }
            Signal(v) => {
                buf.put_string(v.as_ref())?;
            }
            ExitStatus(v) => {
                buf.put_uint32(*v)?;
            }
            ExitSignal(v) => {
                buf.put_string(v.signal().as_ref())?;
                buf.put_boolean(v.coredumped())?;
                buf.put_string(v.error_message())?;
                buf.put_string(v.language_tag())?;
            }
            Unknown {data, ..} => {
                buf.put_slice(&data);
            }
        }
        Ok(())
    }
}

impl From<ChannelRequest> for Message {
    fn from(v: ChannelRequest) -> Self {
        Self::ChannelRequest(v)
    }
}

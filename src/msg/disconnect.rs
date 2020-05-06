use derive_new::new;

use super::*;

#[derive(Debug)]
pub(crate) enum ReasonCode {
    HostNotAllowedToConnect,
    ProtocolError,
    KeyExchangeFailed,
    Reserved,
    MacError,
    CompressionError,
    ServiceNotAvailable,
    ProtocolVersionNotSupported,
    HostKeyNotVerifiable,
    ConnectionLost,
    ByApplication,
    TooManyConnections,
    AuthCancelledByUser,
    NoMoreAuthMethodsAvailable,
    IllegalUserName,
    Unknown(u32),
}

impl Pack for ReasonCode {
    fn pack<P: Put>(&self, buf: &mut P) {
        match self {
            Self::HostNotAllowedToConnect => 1,
            Self::ProtocolError => 2,
            Self::KeyExchangeFailed => 3,
            Self::Reserved => 4,
            Self::MacError => 5,
            Self::CompressionError => 6,
            Self::ServiceNotAvailable => 7,
            Self::ProtocolVersionNotSupported => 8,
            Self::HostKeyNotVerifiable => 9,
            Self::ConnectionLost => 10,
            Self::ByApplication => 11,
            Self::TooManyConnections => 12,
            Self::AuthCancelledByUser => 13,
            Self::NoMoreAuthMethodsAvailable => 14,
            Self::IllegalUserName => 15,
            Self::Unknown(v) => *v,
        }
        .pack(buf);
    }
}

impl Unpack for ReasonCode {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let n = u32::unpack(buf)?;
        Ok(match n {
            1 => Self::HostNotAllowedToConnect,
            2 => Self::ProtocolError,
            3 => Self::KeyExchangeFailed,
            4 => Self::Reserved,
            5 => Self::MacError,
            6 => Self::CompressionError,
            7 => Self::ServiceNotAvailable,
            8 => Self::ProtocolVersionNotSupported,
            9 => Self::HostKeyNotVerifiable,
            10 => Self::ConnectionLost,
            11 => Self::ByApplication,
            12 => Self::TooManyConnections,
            13 => Self::AuthCancelledByUser,
            14 => Self::NoMoreAuthMethodsAvailable,
            15 => Self::IllegalUserName,
            v => Self::Unknown(v),
        })
    }
}

#[derive(Debug, new)]
pub(crate) struct Disconnect {
    reason_code: ReasonCode,
    description: String,
    language_tag: String,
}

impl MsgItem for Disconnect {
    const ID: u8 = 1;
}

impl Pack for Disconnect {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.reason_code.pack(buf);
        self.description.pack(buf);
        self.language_tag.pack(buf);
    }
}

impl Unpack for Disconnect {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let reason_code = Unpack::unpack(buf)?;
        let description = Unpack::unpack(buf)?;
        let language_tag = Unpack::unpack(buf)?;

        Ok(Self {
            reason_code,
            description,
            language_tag,
        })
    }
}

impl From<Disconnect> for Msg {
    fn from(v: Disconnect) -> Self {
        Self::Disconnect(v)
    }
}

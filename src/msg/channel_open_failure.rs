use derive_new::new;

use super::*;

#[derive(Debug)]
pub(crate) enum ReasonCode {
    AdministrativeryProhibited,
    ConnectFailed,
    UnknownChannelType,
    ResourceShortage,
    Unknown(u32),
}

impl Pack for ReasonCode {
    fn pack<P: Put>(&self, buf: &mut P) {
        let n = match self {
            Self::AdministrativeryProhibited => 1,
            Self::ConnectFailed => 2,
            Self::UnknownChannelType => 3,
            Self::ResourceShortage => 4,
            Self::Unknown(v) => *v,
        };
        n.pack(buf);
    }
}

impl Unpack for ReasonCode {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let n = u32::unpack(buf)?;
        Ok(match n {
            1 => Self::AdministrativeryProhibited,
            2 => Self::ConnectFailed,
            3 => Self::UnknownChannelType,
            4 => Self::ResourceShortage,
            v => Self::Unknown(v),
        })
    }
}

#[derive(Debug, new)]
pub(crate) struct ChannelOpenFailure {
    recipient_channel: u32,
    reason_code: ReasonCode,
    description: String,
    language_tag: String,
}

impl MsgItem for ChannelOpenFailure {
    const ID: u8 = 92;
}

impl Pack for ChannelOpenFailure {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.recipient_channel.pack(buf);
        self.reason_code.pack(buf);
        self.description.pack(buf);
        self.language_tag.pack(buf);
    }
}

impl Unpack for ChannelOpenFailure {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let recipient_channel = Unpack::unpack(buf)?;
        let reason_code = Unpack::unpack(buf)?;
        let description = Unpack::unpack(buf)?;
        let language_tag = Unpack::unpack(buf)?;

        Ok(Self {
            recipient_channel,
            reason_code,
            description,
            language_tag,
        })
    }
}

impl From<ChannelOpenFailure> for Msg {
    fn from(v: ChannelOpenFailure) -> Self {
        Self::ChannelOpenFailure(v)
    }
}

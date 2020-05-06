use derive_new::new;

use super::*;

#[derive(Debug)]
pub(crate) enum DataTypeCode {
    Stderr,
    Unknown(u32),
}

impl Pack for DataTypeCode {
    fn pack<P: Put>(&self, buf: &mut P) {
        match self {
            Self::Stderr => 1,
            Self::Unknown(v) => *v,
        }
        .pack(buf)
    }
}

impl Unpack for DataTypeCode {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        Ok(match u32::unpack(buf)? {
            1 => Self::Stderr,
            v => Self::Unknown(v),
        })
    }
}

#[derive(Debug, new)]
pub(crate) struct ChannelExtendedData {
    recipient_channel: u32,
    data_type_code: DataTypeCode,
    data: Bytes,
}

impl MsgItem for ChannelExtendedData {
    const ID: u8 = 95;
}

impl Pack for ChannelExtendedData {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.recipient_channel.pack(buf);
        self.data_type_code.pack(buf);
        self.data.pack(buf);
    }
}

impl Unpack for ChannelExtendedData {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let recipient_channel = Unpack::unpack(buf)?;
        let data_type_code = Unpack::unpack(buf)?;
        let data = Unpack::unpack(buf)?;

        Ok(Self {
            recipient_channel,
            data_type_code,
            data,
        })
    }
}

impl From<ChannelExtendedData> for Msg {
    fn from(v: ChannelExtendedData) -> Self {
        Self::ChannelExtendedData(v)
    }
}

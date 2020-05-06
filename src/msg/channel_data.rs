use derive_new::new;
use getset::Getters;

use super::*;

#[derive(Debug, new, Getters)]
pub(crate) struct ChannelData {
    #[get = "pub(crate)"]
    recipient_channel: u32,
    #[get = "pub(crate)"]
    data: Bytes,
}

impl MsgItem for ChannelData {
    const ID: u8 = 94;
}

impl Pack for ChannelData {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.recipient_channel.pack(buf);
        self.data.pack(buf);
    }
}

impl Unpack for ChannelData {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let recipient_channel = Unpack::unpack(buf)?;
        let data = Unpack::unpack(buf)?;

        Ok(Self {
            recipient_channel,
            data,
        })
    }
}

impl From<ChannelData> for Msg {
    fn from(v: ChannelData) -> Self {
        Self::ChannelData(v)
    }
}

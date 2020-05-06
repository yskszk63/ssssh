use derive_new::new;
use getset::Getters;

use super::*;

#[derive(Debug, new, Getters)]
pub(crate) struct ChannelEof {
    #[get = "pub(crate)"]
    recipient_channel: u32,
}

impl MsgItem for ChannelEof {
    const ID: u8 = 96;
}

impl Pack for ChannelEof {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.recipient_channel.pack(buf);
    }
}

impl Unpack for ChannelEof {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let recipient_channel = Unpack::unpack(buf)?;

        Ok(Self { recipient_channel })
    }
}

impl From<ChannelEof> for Msg {
    fn from(v: ChannelEof) -> Self {
        Self::ChannelEof(v)
    }
}

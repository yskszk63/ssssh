use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct ChannelSuccess {
    recipient_channel: u32,
}

impl MsgItem for ChannelSuccess {
    const ID: u8 = 99;
}

impl Pack for ChannelSuccess {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.recipient_channel.pack(buf);
    }
}

impl Unpack for ChannelSuccess {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let recipient_channel = Unpack::unpack(buf)?;

        Ok(Self { recipient_channel })
    }
}

impl From<ChannelSuccess> for Msg {
    fn from(v: ChannelSuccess) -> Self {
        Self::ChannelSuccess(v)
    }
}

use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct ChannelFailure {
    recipient_channel: u32,
}

impl MsgItem for ChannelFailure {
    const ID: u8 = 100;
}

impl Pack for ChannelFailure {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.recipient_channel.pack(buf);
    }
}

impl Unpack for ChannelFailure {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let recipient_channel = Unpack::unpack(buf)?;

        Ok(Self { recipient_channel })
    }
}

impl From<ChannelFailure> for Msg {
    fn from(v: ChannelFailure) -> Self {
        Self::ChannelFailure(v)
    }
}

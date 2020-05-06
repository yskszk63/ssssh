use derive_new::new;
use getset::Getters;

use super::*;

#[derive(Debug, new, Getters)]
pub(crate) struct ChannelClose {
    #[get = "pub(crate)"]
    recipient_channel: u32,
}

impl MsgItem for ChannelClose {
    const ID: u8 = 97;
}

impl Pack for ChannelClose {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.recipient_channel.pack(buf);
    }
}

impl Unpack for ChannelClose {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let recipient_channel = Unpack::unpack(buf)?;

        Ok(Self { recipient_channel })
    }
}

impl From<ChannelClose> for Msg {
    fn from(v: ChannelClose) -> Self {
        Self::ChannelClose(v)
    }
}

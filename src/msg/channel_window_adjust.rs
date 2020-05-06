use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct ChannelWindowAdjust {
    recipient_channel: u32,
    bytes_to_add: u32,
}

impl MsgItem for ChannelWindowAdjust {
    const ID: u8 = 93;
}

impl Pack for ChannelWindowAdjust {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.recipient_channel.pack(buf);
        self.bytes_to_add.pack(buf);
    }
}

impl Unpack for ChannelWindowAdjust {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let recipient_channel = Unpack::unpack(buf)?;
        let bytes_to_add = Unpack::unpack(buf)?;

        Ok(Self {
            recipient_channel,
            bytes_to_add,
        })
    }
}

impl From<ChannelWindowAdjust> for Msg {
    fn from(v: ChannelWindowAdjust) -> Self {
        Self::ChannelWindowAdjust(v)
    }
}

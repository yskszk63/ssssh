use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct ChannelOpenConfirmation {
    recipient_channel: u32,
    sender_channel: u32,
    initial_window_size: u32,
    maximum_packet_size: u32,
    additional_data: Bytes,
}

impl MsgItem for ChannelOpenConfirmation {
    const ID: u8 = 91;
}

impl Pack for ChannelOpenConfirmation {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.recipient_channel.pack(buf);
        self.sender_channel.pack(buf);
        self.initial_window_size.pack(buf);
        self.maximum_packet_size.pack(buf);
        buf.put(&*self.additional_data);
    }
}

impl Unpack for ChannelOpenConfirmation {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let recipient_channel = Unpack::unpack(buf)?;
        let sender_channel = Unpack::unpack(buf)?;
        let initial_window_size = Unpack::unpack(buf)?;
        let maximum_packet_size = Unpack::unpack(buf)?;
        let additional_data = buf.copy_to_bytes(buf.remaining());
        Ok(Self {
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            additional_data,
        })
    }
}

impl From<ChannelOpenConfirmation> for Msg {
    fn from(v: ChannelOpenConfirmation) -> Self {
        Self::ChannelOpenConfirmation(v)
    }
}

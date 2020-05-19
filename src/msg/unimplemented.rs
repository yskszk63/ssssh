use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct Unimplemented {
    pkt_seq: u32,
}

impl MsgItem for Unimplemented {
    const ID: u8 = 3;
}

impl Pack for Unimplemented {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.pkt_seq.pack(buf);
    }
}

impl Unpack for Unimplemented {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let pkt_seq = Unpack::unpack(buf)?;

        Ok(Self { pkt_seq })
    }
}

impl From<Unimplemented> for Msg {
    fn from(v: Unimplemented) -> Self {
        Self::Unimplemented(v)
    }
}

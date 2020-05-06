use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct Ignore {
    data: Bytes,
}

impl MsgItem for Ignore {
    const ID: u8 = 2;
}

impl Pack for Ignore {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.data.pack(buf);
    }
}

impl Unpack for Ignore {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let data = Unpack::unpack(buf)?;

        Ok(Self { data })
    }
}

impl From<Ignore> for Msg {
    fn from(v: Ignore) -> Self {
        Self::Ignore(v)
    }
}

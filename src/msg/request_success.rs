use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct RequestSuccess {
    additional_data: Bytes,
}

impl MsgItem for RequestSuccess {
    const ID: u8 = 81;
}

impl Pack for RequestSuccess {
    fn pack<P: Put>(&self, buf: &mut P) {
        buf.put(&self.additional_data);
    }
}

impl Unpack for RequestSuccess {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let additional_data = buf.copy_to_bytes(buf.remaining());

        Ok(Self { additional_data })
    }
}

impl From<RequestSuccess> for Msg {
    fn from(v: RequestSuccess) -> Self {
        Self::RequestSuccess(v)
    }
}

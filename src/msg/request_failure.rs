use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct RequestFailure {}

impl MsgItem for RequestFailure {
    const ID: u8 = 82;
}

impl Pack for RequestFailure {
    fn pack<P: Put>(&self, _buf: &mut P) {}
}

impl Unpack for RequestFailure {
    fn unpack<B: Buf>(_buf: &mut B) -> Result<Self, UnpackError> {
        Ok(Self {})
    }
}

impl From<RequestFailure> for Msg {
    fn from(v: RequestFailure) -> Self {
        Self::RequestFailure(v)
    }
}

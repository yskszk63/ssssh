use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct UserauthSuccess {}

impl MsgItem for UserauthSuccess {
    const ID: u8 = 52;
}

impl Pack for UserauthSuccess {
    fn pack<P: Put>(&self, _buf: &mut P) {}
}

impl Unpack for UserauthSuccess {
    fn unpack<B: Buf>(_buf: &mut B) -> Result<Self, UnpackError> {
        Ok(Self {})
    }
}

impl From<UserauthSuccess> for Msg {
    fn from(v: UserauthSuccess) -> Self {
        Self::UserauthSuccess(v)
    }
}

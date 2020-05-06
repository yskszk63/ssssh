use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct NewKeys {}

impl MsgItem for NewKeys {
    const ID: u8 = 21;
}

impl Pack for NewKeys {
    fn pack<P: Put>(&self, _buf: &mut P) {}
}

impl Unpack for NewKeys {
    fn unpack<B: Buf>(_buf: &mut B) -> Result<Self, UnpackError> {
        Ok(Self {})
    }
}

impl From<NewKeys> for Msg {
    fn from(v: NewKeys) -> Self {
        Self::NewKeys(v)
    }
}

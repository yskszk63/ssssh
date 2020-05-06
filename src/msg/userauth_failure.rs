use derive_new::new;

use super::*;
use crate::pack::NameList;

#[derive(Debug, new)]
pub(crate) struct UserauthFailure {
    authentications: NameList,
    partial_success: bool,
}

impl MsgItem for UserauthFailure {
    const ID: u8 = 51;
}

impl Pack for UserauthFailure {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.authentications.pack(buf);
        self.partial_success.pack(buf);
    }
}

impl Unpack for UserauthFailure {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let authentications = Unpack::unpack(buf)?;
        let partial_success = Unpack::unpack(buf)?;

        Ok(Self {
            authentications,
            partial_success,
        })
    }
}

impl From<UserauthFailure> for Msg {
    fn from(v: UserauthFailure) -> Self {
        Self::UserauthFailure(v)
    }
}

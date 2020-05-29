use derive_new::new;

use super::*;
use crate::hostkey::PublicKey;

#[derive(Debug, new)]
pub(crate) struct UserauthPkOk {
    algorithm: String,
    blob: PublicKey,
}

impl MsgItem<UserauthPkMsg> for UserauthPkOk {
    const ID: u8 = 60;
}

impl Pack for UserauthPkOk {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.algorithm.pack(buf);
        self.blob.pack(buf);
    }
}

impl Unpack for UserauthPkOk {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let algorithm = Unpack::unpack(buf)?;
        let blob = Unpack::unpack(buf)?;
        Ok(Self { algorithm, blob })
    }
}

impl From<UserauthPkOk> for UserauthPkMsg {
    fn from(v: UserauthPkOk) -> Self {
        Self::UserauthPkOk(v)
    }
}

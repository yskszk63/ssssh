//! SSH_MSG_KEX_DH_GEX_GROUP
//!
//! [Diffie-Hellman Group Exchange for](https://tools.ietf.org/html/rfc4419)
use derive_new::new;
use getset::Getters;

use super::*;
use crate::pack::Mpint;

#[derive(Debug, Getters, new)]
pub(crate) struct KexDhGexGroup {
    #[get = "pub(crate)"]
    p: Mpint,

    #[get = "pub(crate)"]
    g: Mpint,
}

impl MsgItem<GexMsg> for KexDhGexGroup {
    const ID: u8 = 31;
}

impl Pack for KexDhGexGroup {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.p.pack(buf);
        self.g.pack(buf);
    }
}

impl Unpack for KexDhGexGroup {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let p = Unpack::unpack(buf)?;
        let g = Unpack::unpack(buf)?;

        Ok(Self { p, g })
    }
}

impl From<KexDhGexGroup> for GexMsg {
    fn from(v: KexDhGexGroup) -> Self {
        Self::KexDhGexGroup(v)
    }
}

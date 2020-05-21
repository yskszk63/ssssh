//! SSH_MSG_KEX_DH_GEX_REQUEST_OLD
//!
//! [Diffie-Hellman Group Exchange for](https://tools.ietf.org/html/rfc4419)
use getset::Getters;

use super::*;

#[derive(Debug, Getters)]
pub(crate) struct KexDhGexRequestOld {
    #[get = "pub(crate)"]
    n: u32,
}

impl MsgItem<GexMsg> for KexDhGexRequestOld {
    const ID: u8 = 30;
}

impl Pack for KexDhGexRequestOld {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.n.pack(buf);
    }
}

impl Unpack for KexDhGexRequestOld {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let n = Unpack::unpack(buf)?;

        Ok(Self { n })
    }
}

impl From<KexDhGexRequestOld> for GexMsg {
    fn from(v: KexDhGexRequestOld) -> Self {
        Self::KexDhGexRequestOld(v)
    }
}

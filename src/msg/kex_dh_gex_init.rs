//! SSH_MSG_KEX_DH_GEX_INIT
//!
//! [Diffie-Hellman Group Exchange for](https://tools.ietf.org/html/rfc4419)
use getset::Getters;

use super::*;
use crate::pack::Mpint;

#[derive(Debug, Getters)]
pub(crate) struct KexDhGexInit {
    #[get = "pub(crate)"]
    e: Mpint,
}

impl MsgItem<GexMsg> for KexDhGexInit {
    const ID: u8 = 32;
}

impl Pack for KexDhGexInit {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.e.pack(buf);
    }
}

impl Unpack for KexDhGexInit {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let e = Unpack::unpack(buf)?;

        Ok(Self { e })
    }
}

impl From<KexDhGexInit> for GexMsg {
    fn from(v: KexDhGexInit) -> Self {
        Self::KexDhGexInit(v)
    }
}

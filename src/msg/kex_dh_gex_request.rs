//! SSH_MSG_KEX_DH_GEX_REQUEST
//!
//! [Diffie-Hellman Group Exchange for](https://tools.ietf.org/html/rfc4419)
use getset::Getters;

use super::*;

#[derive(Debug, Getters)]
pub(crate) struct KexDhGexRequest {
    #[get = "pub(crate)"]
    min: u32,

    #[get = "pub(crate)"]
    n: u32,

    #[get = "pub(crate)"]
    max: u32,
}

impl MsgItem<GexMsg> for KexDhGexRequest {
    const ID: u8 = 34;
}

impl Pack for KexDhGexRequest {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.min.pack(buf);
        self.n.pack(buf);
        self.max.pack(buf);
    }
}

impl Unpack for KexDhGexRequest {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let min = Unpack::unpack(buf)?;
        let n = Unpack::unpack(buf)?;
        let max = Unpack::unpack(buf)?;

        Ok(Self { min, n, max })
    }
}

impl From<KexDhGexRequest> for GexMsg {
    fn from(v: KexDhGexRequest) -> Self {
        Self::KexDhGexRequest(v)
    }
}

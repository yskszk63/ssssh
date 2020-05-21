//! SSH_MSG_KEX_DH_GEX_REPLY
//!
//! [Diffie-Hellman Group Exchange for](https://tools.ietf.org/html/rfc4419)
use derive_new::new;
use getset::Getters;

use crate::hostkey::{PublicKey, Signature};

use super::*;

#[derive(Debug, Getters, new)]
pub(crate) struct KexDhGexReply {
    #[get = "pub(crate)"]
    public_host_key: PublicKey,

    #[get = "pub(crate)"]
    f: Bytes,

    #[get = "pub(crate)"]
    signature: Signature,
}

impl MsgItem<GexMsg> for KexDhGexReply {
    const ID: u8 = 33;
}

impl Pack for KexDhGexReply {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.public_host_key.pack(buf);
        self.f.pack(buf);
        self.signature.pack(buf);
    }
}

impl Unpack for KexDhGexReply {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let public_host_key = Unpack::unpack(buf)?;
        let f = Unpack::unpack(buf)?;
        let signature = Unpack::unpack(buf)?;

        Ok(Self {
            public_host_key,
            f,
            signature,
        })
    }
}

impl From<KexDhGexReply> for GexMsg {
    fn from(v: KexDhGexReply) -> Self {
        Self::KexDhGexReply(v)
    }
}

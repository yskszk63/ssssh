//! SSH_MSG_KEX_ECDH_REPLY
//!
//! [ECDH Key Exchange](https://tools.ietf.org/html/rfc5656#section-4)
use derive_new::new;

use crate::key::{PublicKey, Signature};

use super::*;

#[derive(Debug, new)]
pub(crate) struct KexEcdhReply {
    public_host_key: PublicKey,
    ephemeral_public_key: Bytes,
    signature: Signature,
}

impl MsgItem for KexEcdhReply {
    const ID: u8 = 31;
}

impl Pack for KexEcdhReply {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.public_host_key.pack(buf);
        self.ephemeral_public_key.pack(buf);
        self.signature.pack(buf)
    }
}

impl Unpack for KexEcdhReply {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let public_host_key = Unpack::unpack(buf)?;
        let ephemeral_public_key = Unpack::unpack(buf)?;
        let signature = Unpack::unpack(buf)?;

        Ok(Self {
            public_host_key,
            ephemeral_public_key,
            signature,
        })
    }
}

impl From<KexEcdhReply> for Msg {
    fn from(v: KexEcdhReply) -> Self {
        Self::KexEcdhReply(v)
    }
}

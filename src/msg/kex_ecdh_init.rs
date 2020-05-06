//! SSH_MSG_KEX_ECDH_INIT
//!
//! [ECDH Key Exchange](https://tools.ietf.org/html/rfc5656#section-4)
use getset::Getters;

use super::*;

#[derive(Debug, Getters)]
pub(crate) struct KexEcdhInit {
    #[get = "pub(crate)"]
    ephemeral_public_key: Bytes,
}

impl MsgItem for KexEcdhInit {
    const ID: u8 = 30;
}

impl Pack for KexEcdhInit {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.ephemeral_public_key.pack(buf);
    }
}

impl Unpack for KexEcdhInit {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let ephemeral_public_key = Unpack::unpack(buf)?;

        Ok(Self {
            ephemeral_public_key,
        })
    }
}

impl From<KexEcdhInit> for Msg {
    fn from(v: KexEcdhInit) -> Self {
        Self::KexEcdhInit(v)
    }
}

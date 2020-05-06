use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct UserauthBanner {
    message: String,
    language_tag: String,
}

impl MsgItem for UserauthBanner {
    const ID: u8 = 53;
}

impl Pack for UserauthBanner {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.message.pack(buf);
        self.language_tag.pack(buf);
    }
}

impl Unpack for UserauthBanner {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let message = Unpack::unpack(buf)?;
        let language_tag = Unpack::unpack(buf)?;

        Ok(Self {
            message,
            language_tag,
        })
    }
}

impl From<UserauthBanner> for Msg {
    fn from(v: UserauthBanner) -> Self {
        Self::UserauthBanner(v)
    }
}

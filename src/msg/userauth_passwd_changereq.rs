use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct UserauthPasswdChangereq {
    prompt: String,
    language_tag: String,
}

impl MsgItem for UserauthPasswdChangereq {
    const ID: u8 = 60;
}

impl Pack for UserauthPasswdChangereq {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.prompt.pack(buf);
        self.language_tag.pack(buf);
    }
}

impl Unpack for UserauthPasswdChangereq {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let prompt = Unpack::unpack(buf)?;
        let language_tag = Unpack::unpack(buf)?;

        Ok(Self {
            prompt,
            language_tag,
        })
    }
}

impl From<UserauthPasswdChangereq> for Msg {
    fn from(v: UserauthPasswdChangereq) -> Self {
        Self::UserauthPasswdChangereq(v)
    }
}

use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct Debug {
    always_display: bool,
    message: String,
    language_tag: String,
}

impl MsgItem for Debug {
    const ID: u8 = 4;
}

impl Pack for Debug {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.always_display.pack(buf);
        self.message.pack(buf);
        self.language_tag.pack(buf);
    }
}

impl Unpack for Debug {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let always_display = Unpack::unpack(buf)?;
        let message = Unpack::unpack(buf)?;
        let language_tag = Unpack::unpack(buf)?;

        Ok(Self {
            always_display,
            message,
            language_tag,
        })
    }
}

impl From<Debug> for Msg {
    fn from(v: Debug) -> Self {
        Self::Debug(v)
    }
}

use derive_new::new;

use super::*;

#[derive(Debug, new)]
pub(crate) struct ServiceAccept {
    service_name: String,
}

impl MsgItem for ServiceAccept {
    const ID: u8 = 6;
}

impl Pack for ServiceAccept {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.service_name.pack(buf);
    }
}

impl Unpack for ServiceAccept {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let service_name = Unpack::unpack(buf)?;

        Ok(Self { service_name })
    }
}

impl From<ServiceAccept> for Msg {
    fn from(v: ServiceAccept) -> Self {
        Self::ServiceAccept(v)
    }
}

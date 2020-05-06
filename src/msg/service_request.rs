use getset::Getters;

use super::*;

pub(crate) const SSH_USERAUTH: &str = "ssh-userauth";
pub(crate) const SSH_CONNECTION: &str = "ssh-connection";

#[derive(Debug, Getters)]
pub(crate) struct ServiceRequest {
    #[get = "pub(crate)"]
    service_name: String,
}

impl MsgItem for ServiceRequest {
    const ID: u8 = 5;
}

impl Pack for ServiceRequest {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.service_name.pack(buf);
    }
}

impl Unpack for ServiceRequest {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let service_name = Unpack::unpack(buf)?;

        Ok(Self { service_name })
    }
}

impl From<ServiceRequest> for Msg {
    fn from(v: ServiceRequest) -> Self {
        Self::ServiceRequest(v)
    }
}

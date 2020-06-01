use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::service_accept::ServiceAccept;
use crate::msg::service_request::{ServiceRequest, SSH_CONNECTION, SSH_USERAUTH};
use crate::HandlerError;

use super::{Runner, SshError};

impl<IO, E> Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) async fn on_service_request(
        &mut self,
        service_request: &ServiceRequest,
    ) -> Result<(), SshError> {
        match service_request.service_name().as_ref() {
            SSH_USERAUTH => self.on_userauth().await,
            SSH_CONNECTION => self.on_connection().await,
            x => self.on_unknown_service(x).await,
        }
    }

    async fn on_userauth(&mut self) -> Result<(), SshError> {
        let accept = ServiceAccept::new(SSH_USERAUTH.into());
        self.send(accept).await?;
        Ok(())
    }

    async fn on_connection(&mut self) -> Result<(), SshError> {
        Err(SshError::UnacceptableService(SSH_CONNECTION.into()))
    }

    async fn on_unknown_service(&mut self, name: &str) -> Result<(), SshError> {
        Err(SshError::UnacceptableService(name.into()))
    }
}

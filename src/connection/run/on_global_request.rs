use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::global_request::{GlobalRequest, Type};
use crate::msg::request_failure::RequestFailure;

use crate::HandlerError;

use super::{Runner, SshError};

impl<IO, E, Pty> Runner<IO, E, Pty>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) async fn on_global_request(
        &mut self,
        global_request: &GlobalRequest,
    ) -> Result<(), SshError> {
        match global_request.typ() {
            Type::TcpipForward(..) => {
                log::debug!("not implemented for tcpip forward.");
                let r = RequestFailure::new();
                self.send(r).await?;
            }
            Type::CancelTcpipForward(..) => {
                log::debug!("not implemented for cancel tcpip forward.");
                let r = RequestFailure::new();
                self.send(r).await?;
            }
            Type::Unknown(..) => {
                log::debug!("unknown request.");
                let r = RequestFailure::new();
                self.send(r).await?;
            }
        }
        Ok(())
    }
}

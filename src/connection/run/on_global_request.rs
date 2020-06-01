use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::global_request::{GlobalRequest, Type};
use crate::msg::request_failure::RequestFailure;
use crate::msg::request_success::RequestSuccess;

use crate::HandlerError;

use super::{Runner, SshError};

impl<IO, E> Runner<IO, E>
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
                let r = RequestSuccess::new(vec![0x00].into());
                self.send(r).await?;
            }
            _ => {
                let r = RequestFailure::new();
                self.send(r).await?;
            }
        }
        Ok(())
    }
}

use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::global_request::{GlobalRequest, Type};
use crate::msg::request_failure::RequestFailure;
use crate::msg::request_success::RequestSuccess;

use crate::Handlers;

use super::{Runner, SshError};

impl<IO, H> Runner<IO, H>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handlers,
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

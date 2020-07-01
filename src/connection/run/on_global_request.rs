use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::global_request::GlobalRequest;
use crate::msg::request_failure::RequestFailure;

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
            _ => {
                let r = RequestFailure::new();
                self.send(r).await?;
            }
        }
        Ok(())
    }
}

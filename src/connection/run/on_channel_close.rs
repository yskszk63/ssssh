use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::channel_close::ChannelClose;
use crate::HandlerError;

use super::{Runner, SshError};

impl<IO, E> Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) async fn on_channel_close(
        &mut self,
        channel_close: &ChannelClose,
    ) -> Result<(), SshError> {
        let chid = channel_close.recipient_channel();
        self.channels.remove(chid);
        Ok(())
    }
}

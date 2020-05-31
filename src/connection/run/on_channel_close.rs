use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::channel_close::ChannelClose;
use crate::Handlers;

use super::{Runner, SshError};

impl<IO, H> Runner<IO, H>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handlers,
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

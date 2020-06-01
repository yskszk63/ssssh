use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::channel_window_adjust::ChannelWindowAdjust;
use crate::HandlerError;

use super::{Runner, SshError};

impl<IO, E> Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) async fn on_channel_window_adjust(
        &mut self,
        channel_window_adjust: &ChannelWindowAdjust,
    ) -> Result<(), SshError> {
        // FIXME window adjust management
        let m = ChannelWindowAdjust::new(
            *channel_window_adjust.recipient_channel(),
            *channel_window_adjust.bytes_to_add(),
        );
        self.send(m).await
    }
}

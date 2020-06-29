use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};

use crate::msg::channel_eof::ChannelEof;
use crate::HandlerError;

use super::{Channel, Runner, SshError};

impl<IO, E> Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) async fn on_channel_eof(
        &mut self,
        channel_eof: &ChannelEof,
    ) -> Result<(), SshError> {
        let chid = channel_eof.recipient_channel();
        if let Some(channel) = self.channels.get_mut(chid) {
            match channel {
                Channel::Session(_, stdin, _) | Channel::DirectTcpip(_, stdin) => {
                    if let Some(mut stdin) = stdin.take() {
                        stdin.shutdown().await?;
                    }
                }
            }
        }
        Ok(())
    }
}

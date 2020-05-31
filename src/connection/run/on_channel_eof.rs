use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::channel_eof::ChannelEof;
use crate::Handlers;

use super::{Channel, Runner, SshError};

impl<IO, H> Runner<IO, H>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handlers,
{
    pub(super) async fn on_channel_eof(
        &mut self,
        channel_eof: &ChannelEof,
    ) -> Result<(), SshError> {
        let chid = channel_eof.recipient_channel();
        if let Some(channel) = self.channels.get_mut(chid) {
            match channel {
                Channel::Session(_, stdin, _) => {
                    if let Some(stdin) = stdin.take() {
                        stdin.close_channel()
                    }
                }
            }
        }
        Ok(())
    }
}

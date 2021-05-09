use log::warn;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

use crate::msg::channel_data::ChannelData;
use crate::HandlerError;

use super::{Channel, Runner, SshError};

impl<IO, E> Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) async fn on_channel_data(
        &mut self,
        channel_data: &ChannelData,
    ) -> Result<(), SshError> {
        let chid = channel_data.recipient_channel();
        let data = channel_data.data().as_ref();
        if let Some(channel) = self.channels.get_mut(chid) {
            match channel {
                Channel::Session(_, stdin, _, _) | Channel::DirectTcpip(_, stdin) => match stdin {
                    Some(stdin) => {
                        stdin.write_all(&data).await?;
                    }
                    None => warn!("closed channel {}", chid),
                },
            }
        }
        Ok(())
    }
}

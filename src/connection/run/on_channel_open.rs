use futures::channel::mpsc;
use futures::stream::StreamExt as _;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::channel_open::{ChannelOpen, Type};
use crate::msg::channel_open_confirmation::ChannelOpenConfirmation;
use crate::msg::channel_open_failure::{ChannelOpenFailure, ReasonCode};
use crate::Handlers;

use super::{Channel, Runner, SshError};

impl<IO, H> Runner<IO, H>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handlers,
{
    pub(super) async fn on_channel_open(
        &mut self,
        channel_open: &ChannelOpen,
    ) -> Result<(), SshError> {
        match channel_open.typ() {
            Type::Session(..) => self.on_channel_open_session(channel_open).await,
            x => {
                debug!("unknown channel type {:?}", x);

                let msg = ChannelOpenFailure::new(
                    *channel_open.sender_channel(),
                    ReasonCode::UnknownChannelType,
                    "unknown channel".into(),
                    "en-US".into(),
                );
                self.send(msg).await?;
                Ok(())
            }
        }
    }

    async fn on_channel_open_session(
        &mut self,
        channel_open: &ChannelOpen,
    ) -> Result<(), SshError> {
        let chid = *channel_open.sender_channel();
        let (stdin_tx, stdin_rx) = mpsc::unbounded();
        let stdin_rx = stdin_rx.fuse();

        let channel = Channel::Session(chid, Some(stdin_tx), Some(stdin_rx));
        if self.channels.contains_key(&chid) {
            // already exists
            let msg = ChannelOpenFailure::new(
                *channel_open.sender_channel(),
                ReasonCode::AdministrativeryProhibited,
                "already opened".into(),
                "en-US".into(),
            );
            self.send(msg).await?;
        } else {
            self.channels.insert(chid, channel);

            let ok = ChannelOpenConfirmation::new(
                *channel_open.sender_channel(),
                *channel_open.sender_channel(),
                *channel_open.initial_window_size(),
                *channel_open.maximum_packet_size(),
                "".into(),
            );
            self.send(ok).await?;
        }
        Ok(())
    }
}

use std::collections::hash_map::Entry;

use futures::channel::mpsc;
use futures::future::TryFutureExt as _;
use futures::sink::SinkExt as _;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::channel_close::ChannelClose;
use crate::msg::channel_open::{ChannelOpen, DirectTcpip, Type};
use crate::msg::channel_open_confirmation::ChannelOpenConfirmation;
use crate::msg::channel_open_failure::{ChannelOpenFailure, ReasonCode};
use crate::HandlerError;

use super::{Channel, Runner, SshError, SshInput, SshOutput};

impl<IO, E> Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) async fn on_channel_open(
        &mut self,
        channel_open: &ChannelOpen,
    ) -> Result<(), SshError> {
        match channel_open.typ() {
            Type::Session(..) => self.on_channel_open_session(channel_open).await,
            Type::DirectTcpip(item) => self.on_channel_open_direct_tcpip(channel_open, item).await,
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
        let stdin_rx = SshInput::new(stdin_rx);

        let channel = Channel::Session(chid, Some(stdin_tx), Some(stdin_rx));
        if let Entry::Vacant(entry) = self.channels.entry(chid) {
            entry.insert(channel);

            let ok = ChannelOpenConfirmation::new(
                *channel_open.sender_channel(),
                *channel_open.sender_channel(),
                *channel_open.initial_window_size(),
                *channel_open.maximum_packet_size(),
                "".into(),
            );
            self.send(ok).await?;
        } else {
            // already exists
            let msg = ChannelOpenFailure::new(
                *channel_open.sender_channel(),
                ReasonCode::AdministrativeryProhibited,
                "already opened".into(),
                "en-US".into(),
            );
            self.send(msg).await?;
        }
        Ok(())
    }

    async fn on_channel_open_direct_tcpip(
        &mut self,
        channel_open: &ChannelOpen,
        _item: &DirectTcpip,
    ) -> Result<(), SshError> {
        let chid = *channel_open.sender_channel();
        let (stdin_tx, stdin_rx) = mpsc::unbounded();

        let input = SshInput::new(stdin_rx);
        let output = SshOutput::new(chid, self.outbound_channel_tx.clone());

        let channel = Channel::DirectTcpip(chid, Some(stdin_tx));
        if let Entry::Vacant(entry) = self.channels.entry(chid) {
            entry.insert(channel);

            let mut tx = self.outbound_channel_tx.clone();
            if let Some(fut) = self.handlers.dispatch_direct_tcpip(input, output) {
                self.completions.push(
                    fut.and_then(move |_| async move {
                        let msg = ChannelClose::new(chid).into();
                        tx.send(msg).await.ok(); // FIXME

                        Ok(())
                    })
                    .map_err(Into::into),
                );

                let msg = ChannelOpenConfirmation::new(
                    *channel_open.sender_channel(),
                    *channel_open.sender_channel(),
                    *channel_open.initial_window_size(),
                    *channel_open.maximum_packet_size(),
                    "".into(),
                );
                self.send(msg).await?;
            } else {
                // FIXME unimplemented
                let msg = ChannelOpenFailure::new(
                    *channel_open.sender_channel(),
                    ReasonCode::AdministrativeryProhibited,
                    "already opened".into(),
                    "en-US".into(),
                );
                self.send(msg).await?;
            }
        } else {
            // already exists
            let msg = ChannelOpenFailure::new(
                *channel_open.sender_channel(),
                ReasonCode::AdministrativeryProhibited,
                "already opened".into(),
                "en-US".into(),
            );
            self.send(msg).await?;
        }
        Ok(())
    }
}

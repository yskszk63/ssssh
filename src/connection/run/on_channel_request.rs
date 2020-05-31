use std::os::unix::ffi::OsStringExt;

use futures::future::TryFutureExt as _;
use futures::sink::SinkExt as _;
use futures::stream::StreamExt as _;
use tokio::io::{self, AsyncRead, AsyncWrite};

use crate::msg::channel_close::ChannelClose;
use crate::msg::channel_failure::ChannelFailure;
use crate::msg::channel_request::{ChannelRequest, Type};
use crate::msg::channel_success::ChannelSuccess;

use crate::Handlers;

use super::SshStdout;
use super::{Channel, Runner, SshError};

impl<IO, H> Runner<IO, H>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handlers,
{
    pub(super) async fn on_channel_request(
        &mut self,
        channel_request: &ChannelRequest,
    ) -> Result<(), SshError> {
        match channel_request.typ() {
            Type::Shell(..) => self.on_channel_request_shell(channel_request).await,
            Type::Exec(prog) => self.on_channel_request_exec(channel_request, prog).await,
            _ => {
                let r = ChannelFailure::new(*channel_request.recipient_channel());
                self.send(r).await?;
                Ok(())
            }
        }
    }

    pub(super) async fn on_channel_request_shell(
        &mut self,
        channel_request: &ChannelRequest,
    ) -> Result<(), SshError> {
        let chid = channel_request.recipient_channel();
        if let Some(Channel::Session(_, _, stdin)) = self.channels.get_mut(chid) {
            let stdin = io::stream_reader(stdin.take().unwrap().map(Ok));
            let stdout = SshStdout::new(
                *channel_request.recipient_channel(),
                self.outbound_channel_tx.clone(),
                true,
            );
            let stderr = SshStdout::new(
                *channel_request.recipient_channel(),
                self.outbound_channel_tx.clone(),
                false,
            );
            let mut tx = self.outbound_channel_tx.clone();
            let chid = *chid;
            self.completions.push(
                self.handlers
                    .handle_channel_shell(stdin, stdout, stderr)
                    .and_then(move |r| async move {
                        let typ = Type::ExitStatus(r);
                        let msg = ChannelRequest::new(chid, false, typ).into();
                        tx.send(msg).await.ok(); // FIXME

                        let msg = ChannelClose::new(chid).into();
                        tx.send(msg).await.ok(); // FIXME

                        Ok(())
                    })
                    .map_err(Into::into),
            );

            let r = ChannelSuccess::new(*channel_request.recipient_channel());
            self.send(r).await?;
        } else {
            let r = ChannelFailure::new(*channel_request.recipient_channel());
            self.send(r).await?;
        }
        Ok(())
    }

    pub(super) async fn on_channel_request_exec(
        &mut self,
        channel_request: &ChannelRequest,
        prog: &[u8],
    ) -> Result<(), SshError> {
        let chid = channel_request.recipient_channel();
        if let Some(Channel::Session(_, _, stdin)) = self.channels.get_mut(chid) {
            let stdin = io::stream_reader(stdin.take().unwrap().map(Ok));
            let stdout = SshStdout::new(
                *channel_request.recipient_channel(),
                self.outbound_channel_tx.clone(),
                true,
            );
            let stderr = SshStdout::new(
                *channel_request.recipient_channel(),
                self.outbound_channel_tx.clone(),
                false,
            );
            let mut tx = self.outbound_channel_tx.clone();
            let chid = *chid;
            let prog = std::ffi::OsString::from_vec(prog.to_vec());
            self.completions.push(
                self.handlers
                    .handle_channel_exec(stdin, stdout, stderr, prog)
                    .and_then(move |r| async move {
                        let typ = Type::ExitStatus(r);
                        let msg = ChannelRequest::new(chid, false, typ).into();
                        tx.send(msg).await.ok(); // FIXME

                        let msg = ChannelClose::new(chid).into();
                        tx.send(msg).await.ok(); // FIXME

                        Ok(())
                    })
                    .map_err(Into::into),
            );

            let r = ChannelSuccess::new(*channel_request.recipient_channel());
            self.send(r).await?;
        } else {
            let r = ChannelFailure::new(*channel_request.recipient_channel());
            self.send(r).await?;
        }
        Ok(())
    }
}

use std::os::unix::ffi::OsStringExt;

use futures::future::TryFutureExt as _;
use futures::sink::SinkExt as _;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::channel_close::ChannelClose;
use crate::msg::channel_extended_data::DataTypeCode;
use crate::msg::channel_failure::ChannelFailure;
use crate::msg::channel_request::{ChannelRequest, Type};
use crate::msg::channel_success::ChannelSuccess;

use crate::HandlerError;

use super::{Channel, Runner, SshError, SshOutput};

impl<IO, E> Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
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
        let channel = *channel_request.recipient_channel();

        if let Some(Channel::Session(_, _, stdin)) = self.channels.get_mut(&channel) {
            let stdin = stdin.take().unwrap();
            let stdout = SshOutput::new(channel, self.outbound_channel_tx.clone());
            let stderr = SshOutput::new(channel, self.outbound_channel_tx.clone())
                .with_extended(DataTypeCode::Stderr);

            if let Some(fut) = self.handlers.dispatch_channel_shell(stdin, stdout, stderr) {
                let mut tx = self.outbound_channel_tx.clone();
                self.completions.push(
                    fut.and_then(move |r| async move {
                        let typ = Type::ExitStatus(r);
                        let msg = ChannelRequest::new(channel, false, typ).into();
                        tx.send(msg).await.ok(); // FIXME

                        let msg = ChannelClose::new(channel).into();
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
        let channel = *channel_request.recipient_channel();

        if let Some(Channel::Session(_, _, stdin)) = self.channels.get_mut(&channel) {
            let stdin = stdin.take().unwrap();
            let stdout = SshOutput::new(channel, self.outbound_channel_tx.clone());
            let stderr = SshOutput::new(channel, self.outbound_channel_tx.clone())
                .with_extended(DataTypeCode::Stderr);
            let prog = std::ffi::OsString::from_vec(prog.to_vec());

            if let Some(fut) = self
                .handlers
                .dispatch_channel_exec(stdin, stdout, stderr, prog)
            {
                let mut tx = self.outbound_channel_tx.clone();
                self.completions.push(
                    fut.and_then(move |r| async move {
                        let typ = Type::ExitStatus(r);
                        let msg = ChannelRequest::new(channel, false, typ).into();
                        tx.send(msg).await.ok(); // FIXME

                        let msg = ChannelClose::new(channel).into();
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
        } else {
            let r = ChannelFailure::new(*channel_request.recipient_channel());
            self.send(r).await?;
        }
        Ok(())
    }
}

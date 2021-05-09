use std::os::unix::ffi::OsStringExt;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::channel_extended_data::DataTypeCode;
use crate::msg::channel_failure::ChannelFailure;
use crate::msg::channel_request::{ChannelRequest, Type};
use crate::msg::channel_success::ChannelSuccess;

use crate::HandlerError;

use super::{Channel, Runner, SshError};

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
            Type::Env(env) => {
                self.on_channel_request_env(channel_request, env.name(), env.value())
                    .await
            }
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

        if let Some(Channel::Session(_, _, stdin, env)) = self.channels.get_mut(&channel) {
            let env = env.clone();
            let stdin = stdin.take().unwrap();

            let (stdout, stdout_closed) = self.new_output(channel, None).await?;
            let (stderr, stderr_closed) =
                self.new_output(channel, Some(DataTypeCode::Stderr)).await?;

            if let Some(fut) = self
                .handlers
                .dispatch_channel_shell(stdin, stdout, stderr, env)
            {
                self.spawn_shell_handler(channel, stdout_closed, stderr_closed, fut)
                    .await;
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

        if let Some(Channel::Session(_, _, stdin, env)) = self.channels.get_mut(&channel) {
            let env = env.clone();
            let stdin = stdin.take().unwrap();

            let (stdout, stdout_closed) = self.new_output(channel, None).await?;
            let (stderr, stderr_closed) =
                self.new_output(channel, Some(DataTypeCode::Stderr)).await?;

            let prog = std::ffi::OsString::from_vec(prog.to_vec());

            if let Some(fut) = self
                .handlers
                .dispatch_channel_exec(stdin, stdout, stderr, prog, env)
            {
                self.spawn_shell_handler(channel, stdout_closed, stderr_closed, fut)
                    .await;
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

    pub(super) async fn on_channel_request_env(
        &mut self,
        channel_request: &ChannelRequest,
        name: &str,
        value: &str,
    ) -> Result<(), SshError> {
        let channel = *channel_request.recipient_channel();

        if let Some(Channel::Session(_, _, _, ref mut env)) = self.channels.get_mut(&channel) {
            env.insert(name.to_owned(), value.to_owned());
            let r = ChannelSuccess::new(*channel_request.recipient_channel());
            self.send(r).await?;
        } else {
            let r = ChannelFailure::new(*channel_request.recipient_channel());
            self.send(r).await?;
        }
        Ok(())
    }
}

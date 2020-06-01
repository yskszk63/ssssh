use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use futures::channel::mpsc;
use futures::future::Either;
use futures::sink::SinkExt as _;
use futures::stream::Fuse;
use futures::stream::StreamExt as _;
use futures::stream::TryStreamExt as _;
use log::{debug, error, warn};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;

use crate::handlers::{HandlerError, Handlers};
use crate::msg::{self, Msg};
use crate::preference::Preference;
use crate::stream::msg::MsgStream;
use crate::SshError;

use super::completion_stream::CompletionStream;
use super::ssh_stream::{SshInput, SshOutput};

mod on_channel_close;
mod on_channel_data;
mod on_channel_eof;
mod on_channel_open;
mod on_channel_request;
mod on_channel_window_adjust;
mod on_global_request;
mod on_kexinit;
mod on_service_request;
mod on_userauth_request;

#[derive(Debug)]
enum Channel {
    Session(u32, Option<mpsc::UnboundedSender<Bytes>>, Option<SshInput>),
    DirectTcpip(u32, Option<mpsc::UnboundedSender<Bytes>>),
}

fn maybe_timeout(preference: &Preference) -> impl Future<Output = ()> {
    if let Some(timeout) = preference.timeout() {
        Either::Left(time::delay_for(*timeout))
    } else {
        Either::Right(futures::future::pending())
    }
}

#[derive(Debug)]
pub(super) struct Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    io: MsgStream<IO>,
    c_version: String,
    s_version: String,
    preference: Arc<Preference>,
    handlers: Handlers<E>,
    channels: HashMap<u32, Channel>,
    outbound_channel_tx: mpsc::UnboundedSender<Msg>,
    outbound_channel_rx: Fuse<mpsc::UnboundedReceiver<Msg>>,
    completions: CompletionStream<Result<(), HandlerError>>,
    first_kexinit: Option<msg::kexinit::Kexinit>,
}

impl<IO, E> Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) fn new(
        io: MsgStream<IO>,
        c_version: String,
        s_version: String,
        preference: Arc<Preference>,
        handlers: Handlers<E>,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded();
        let rx = rx.fuse();

        Self {
            io,
            c_version,
            s_version,
            preference,
            handlers,
            channels: Default::default(),
            outbound_channel_tx: tx,
            outbound_channel_rx: rx,
            completions: CompletionStream::new(),
            first_kexinit: None,
        }
    }

    async fn send<M: Into<Msg>>(&mut self, msg: M) -> Result<(), SshError> {
        self.io.send(msg.into()).await
    }

    pub(super) async fn run(mut self) -> Result<(), SshError> {
        debug!("connection running...");
        let result = self.r#loop().await;
        if let Err(e) = &result {
            error!("error ocurred {}", e);
            let t = e
                .reason_code()
                .unwrap_or_else(|| msg::disconnect::ReasonCode::ProtocolError);
            let msg = msg::disconnect::Disconnect::new(t, "error occurred".into(), "".into());
            if let Err(e) = self.send(msg).await {
                error!("failed to send disconnect: {}", e)
            }
        }
        debug!("connection done.");
        result
    }

    async fn r#loop(&mut self) -> Result<(), SshError> {
        let first_kexinit = self.preference.to_kexinit();
        self.send(first_kexinit.clone()).await?;
        self.first_kexinit = Some(first_kexinit);

        let mut connected = true;

        while connected {
            let mut timeout = maybe_timeout(&self.preference);

            tokio::select! {
                Ok(msg) = self.io.try_next() => {
                    if let Some(msg) = msg {
                        self.handle_msg(&msg, &mut connected).await?;
                    } else {
                        connected = false;
                    }
                }
                Some(msg) = self.outbound_channel_rx.next() => self.send(msg).await?,
                Some(completed) = self.completions.next() => completed.map_err(SshError::HandlerError)?,
                _ = &mut timeout => {
                    let t = msg::disconnect::ReasonCode::ConnectionLost;
                    let msg = msg::disconnect::Disconnect::new(
                        t,
                        "timedout".into(),
                        "".into(),
                    );
                    if let Err(e) = self.send(msg).await {
                        warn!("failed to send disconnect: {}", e);
                    }
                    connected = false
                }
            }
        }
        Ok(())
    }

    async fn handle_msg(&mut self, msg: &msg::Msg, connected: &mut bool) -> Result<(), SshError> {
        match &msg {
            Msg::Kexinit(msg) => self.on_kexinit(msg).await?,
            Msg::ServiceRequest(msg) => self.on_service_request(msg).await?,
            Msg::UserauthRequest(msg) => self.on_userauth_request(msg).await?,
            Msg::GlobalRequest(msg) => self.on_global_request(msg).await?,
            Msg::ChannelOpen(msg) => self.on_channel_open(msg).await?,
            Msg::ChannelData(msg) => self.on_channel_data(msg).await?,
            Msg::ChannelEof(msg) => self.on_channel_eof(msg).await?,
            Msg::ChannelClose(msg) => self.on_channel_close(msg).await?,
            Msg::ChannelWindowAdjust(msg) => self.on_channel_window_adjust(msg).await?,
            Msg::ChannelRequest(msg) => self.on_channel_request(msg).await?,
            Msg::Disconnect(..) => *connected = false,
            Msg::Ignore(..) => {}
            Msg::Unimplemented(..) => {}
            x => {
                warn!("UNHANDLED {:?}", x);

                let last_seq = self.io.get_ref().state().ctos().seq();
                let m = msg::unimplemented::Unimplemented::new(last_seq);
                self.send(m).await?;
            }
        }

        Ok(())
    }
}

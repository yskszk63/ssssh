use bytes::Bytes;
use failure::Fail;
use futures::channel::mpsc;
use futures::SinkExt as _;

use crate::msg::{self, Message};

#[derive(Debug, Fail)]
#[fail(display = "Failed to send")]
pub struct SendError;

pub type SendResult = Result<(), SendError>;

#[derive(Debug, Clone)]
pub enum Signal {
    Abrt,
    Alrm,
    Fpe,
    Hup,
    Ill,
    Int,
    Kill,
    Pipe,
    Quit,
    Segv,
    Term,
    Usr1,
    Usr2,
    Unknown(String),
}

impl From<Signal> for msg::Signal {
    fn from(v: Signal) -> Self {
        match v {
            Signal::Abrt => Self::Abrt,
            Signal::Alrm => Self::Alrm,
            Signal::Fpe => Self::Fpe,
            Signal::Hup => Self::Hup,
            Signal::Ill => Self::Ill,
            Signal::Int => Self::Int,
            Signal::Kill => Self::Kill,
            Signal::Pipe => Self::Pipe,
            Signal::Quit => Self::Quit,
            Signal::Segv => Self::Segv,
            Signal::Term => Self::Term,
            Signal::Usr1 => Self::Usr1,
            Signal::Usr2 => Self::Usr2,
            Signal::Unknown(s) => Self::Unknown(s),
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct GlobalHandle {
    tx: mpsc::Sender<Message>,
    remote: String,
}

impl GlobalHandle {
    pub(crate) fn new(tx: mpsc::Sender<Message>, remote: &str) -> Self {
        let remote = remote.into();
        Self { tx, remote }
    }

    pub(crate) fn remote(&self) -> &str {
        &self.remote
    }

    pub(crate) fn new_channel_handle(&self, channel: u32) -> ChannelHandle {
        ChannelHandle {
            global: self.clone(),
            channel,
        }
    }

    pub(crate) fn new_auth_handle(&self) -> AuthHandle {
        AuthHandle {
            global: self.clone(),
        }
    }

    pub async fn send_debug(
        &mut self,
        always_display: bool,
        msg: impl Into<String>,
        language_tag: impl Into<String>,
    ) -> SendResult {
        self.send(msg::Debug::new(
            always_display,
            msg.into(),
            language_tag.into(),
        ))
        .await
    }

    async fn send(&mut self, msg: impl Into<Message>) -> SendResult {
        self.tx.send(msg.into()).await.map_err(|_| SendError)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct AuthHandle {
    global: GlobalHandle,
}

impl AuthHandle {
    pub async fn send_debug(
        &mut self,
        always_display: bool,
        msg: impl Into<String>,
        language_tag: impl Into<String>,
    ) -> SendResult {
        self.global
            .send_debug(always_display, msg.into(), language_tag.into())
            .await
    }

    pub fn remote(&self) -> &str {
        self.global.remote()
    }

    pub async fn send_banner(
        &mut self,
        msg: impl Into<String>,
        language_tag: impl Into<String>,
    ) -> SendResult {
        self.global
            .send(msg::UserauthBanner::new(msg.into(), language_tag.into()))
            .await
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct ChannelHandle {
    global: GlobalHandle,
    channel: u32,
}

impl ChannelHandle {
    pub fn channel_id(&self) -> u32 {
        self.channel
    }

    pub fn remote(&self) -> &str {
        self.global.remote()
    }

    pub async fn send_debug(
        &mut self,
        always_display: bool,
        msg: impl Into<String>,
        language_tag: impl Into<String>,
    ) -> SendResult {
        self.global
            .send_debug(always_display, msg.into(), language_tag.into())
            .await
    }

    pub async fn send_data(&mut self, msg: impl Into<Bytes>) -> SendResult {
        self.global
            .send(msg::ChannelData::new(self.channel, msg.into()))
            .await
    }

    pub async fn send_extended_data(&mut self, msg: impl Into<Bytes>) -> SendResult {
        self.global
            .send(msg::ChannelExtendedData::new(self.channel, msg.into()))
            .await
    }

    pub async fn send_exit_status(&mut self, status: u32) -> SendResult {
        self.global
            .send(msg::ChannelRequest::new_exit_status(self.channel, status))
            .await
    }

    pub async fn send_exit_signal(
        &mut self,
        signal: Signal,
        coredumped: bool,
        error_message: impl Into<String>,
        language_tag: impl Into<String>,
    ) -> SendResult {
        self.global
            .send(msg::ChannelRequest::new_exit_signal(
                self.channel,
                signal.into(),
                coredumped,
                error_message,
                language_tag,
            ))
            .await
    }

    pub async fn send_eof(&mut self) -> SendResult {
        self.global.send(msg::ChannelEof::new(self.channel)).await
    }

    pub async fn send_close(&mut self) -> SendResult {
        self.global.send(msg::ChannelClose::new(self.channel)).await
    }
}

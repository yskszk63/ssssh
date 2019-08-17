use bytes::Bytes;
use tokio::sync::mpsc;

use crate::msg::{self, Message};

#[derive(Debug, Clone)]
#[allow(clippy::module_name_repetitions)]
pub struct GlobalHandle {
    tx: mpsc::Sender<Message>,
}

impl GlobalHandle {
    pub(crate) fn new(tx: mpsc::Sender<Message>) -> Self {
        Self { tx }
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
    ) {
        self.send(msg::Debug::new(
            always_display,
            msg.into(),
            language_tag.into(),
        ))
        .await;
    }

    async fn send(&mut self, msg: impl Into<Message>) {
        self.tx.send(msg.into()).await.unwrap();
    }
}

#[derive(Debug)]
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
    ) {
        self.global
            .send_debug(always_display, msg.into(), language_tag.into())
            .await
    }

    pub async fn send_banner(&mut self, msg: impl Into<String>, language_tag: impl Into<String>) {
        self.global
            .send(msg::UserauthBanner::new(msg.into(), language_tag.into()))
            .await
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct ChannelHandle {
    global: GlobalHandle,
    channel: u32,
}

impl ChannelHandle {
    pub async fn send_debug(
        &mut self,
        always_display: bool,
        msg: impl Into<String>,
        language_tag: impl Into<String>,
    ) {
        self.global
            .send_debug(always_display, msg.into(), language_tag.into())
            .await
    }

    pub async fn send_data(&mut self, msg: impl Into<Bytes>) {
        self.global
            .send(msg::ChannelData::new(self.channel, msg.into()))
            .await
    }

    pub async fn send_extended_data(&mut self, msg: impl Into<Bytes>) {
        self.global
            .send(msg::ChannelExtendedData::new(self.channel, msg.into()))
            .await
    }

    pub async fn send_eof(&mut self) {
        self.global.send(msg::ChannelEof::new(self.channel)).await
    }

    pub async fn send_close(&mut self) {
        self.global.send(msg::ChannelClose::new(self.channel)).await
    }
}

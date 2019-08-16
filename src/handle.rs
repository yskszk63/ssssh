use tokio::sync::mpsc;
use bytes::Bytes;

use crate::msg::{self, Message};

#[derive(Debug, Clone)]
pub struct GlobalHandle {
    tx: mpsc::Sender<Message>,
}

impl GlobalHandle {
    pub(crate) fn new(tx: mpsc::Sender<Message>) -> Self {
        Self { tx }
    }

    pub(crate) fn new_channel_handle(&self, channel: u32) -> ChannelHandle {
        ChannelHandle { global: self.clone(), channel }
    }

    pub async fn send_debug(
        &mut self, always_display: bool, msg: impl Into<String>, language_tag: impl Into<String>) {
        self.send(msg::Debug::new(always_display, msg.into(), language_tag.into())).await;
    }

    async fn send(&mut self, msg: impl Into<Message>) {
        self.tx.send(msg.into()).await.unwrap();
    }
}

#[derive(Debug)]
pub struct ChannelHandle {
    global: GlobalHandle,
    channel: u32,
}

impl ChannelHandle {
    pub async fn send_data(&mut self, msg: impl Into<Bytes>) {
        self.global.send(msg::ChannelData::new(self.channel, msg.into())).await
    }

    pub async fn send_extended_data(&mut self, msg: impl Into<Bytes>) {
        self.global.send(msg::ChannelExtendedData::new(self.channel, msg.into())).await
    }

    pub async fn send_eof(&mut self) {
        self.global.send(msg::ChannelEof::new(self.channel)).await
    }

    pub async fn send_close(&mut self) {
        self.global.send(msg::ChannelClose::new(self.channel)).await
    }
}

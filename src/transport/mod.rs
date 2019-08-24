use std::convert::TryFrom as _;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::BytesMut;
use futures::{ready, Sink, Stream};
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use tokio::codec::Framed;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::{Message, MessageError, MessageResult};
use codec::Codec;
pub(crate) use state::State;
pub(crate) use codec::CodecError;
pub(crate) use packet::Packet;

mod codec;
mod state;
pub(crate) mod version;
mod packet;

#[derive(Debug)]
pub(crate) struct Transport<IO> {
    io: Framed<IO, Codec<StdRng>>,
}

impl<IO> Transport<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(io: IO, rbuf: BytesMut, state: Arc<Mutex<State>>) -> Self {
        let rng = StdRng::from_entropy();
        let mut parts = Framed::new(io, Codec::new(rng, state)).into_parts();
        parts.read_buf = rbuf;
        let io = Framed::from_parts(parts);

        Self { io }
    }
}

impl<IO> Stream for Transport<IO>
where
    IO: AsyncRead + Unpin,
{
    type Item = MessageResult<(u32, Message)>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.io)
            .poll_next(cx)
            .map(|opt| opt.map(|v| {
                let v = v?;
                Message::try_from(v.data()).map(|m| (v.seq(), m))
            }))
    }
}

impl<IO> Sink<Message> for Transport<IO>
where
    IO: AsyncWrite + Unpin,
{
    type Error = MessageError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<MessageResult<()>> {
        Poll::Ready(Ok(ready!(Pin::new(&mut self.io).poll_ready(cx))?))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> MessageResult<()> {
        let mut buf = BytesMut::with_capacity(1024 * 8 * 1024); // TODO
        item.put(&mut buf)?;
        Ok(Pin::new(&mut self.io).start_send(buf.freeze())?)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<MessageResult<()>> {
        Poll::Ready(Ok(ready!(Pin::new(&mut self.io).poll_flush(cx))?))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<MessageResult<()>> {
        Poll::Ready(Ok(ready!(Pin::new(&mut self.io).poll_close(cx))?))
    }
}

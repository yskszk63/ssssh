use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::buf::Buf as _;
use bytes::Bytes;
use futures::channel::mpsc;
use futures::ready;
use futures::sink::Sink;
use futures::stream::Stream;
use tokio::io::{self, AsyncRead, AsyncWrite, StreamReader};

use crate::msg::channel_data::ChannelData;
use crate::msg::channel_eof::ChannelEof;
use crate::msg::channel_extended_data::{ChannelExtendedData, DataTypeCode};
use crate::msg::Msg;

#[derive(Debug)]
struct OkStream<S>(S);

impl<S> Stream for OkStream<S>
where
    S: Stream<Item = Bytes> + Unpin,
{
    type Item = io::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match ready!(Pin::new(&mut self.0).poll_next(cx)) {
            Some(item) => Poll::Ready(Some(Ok(item))),
            None => Poll::Ready(None),
        }
    }
}

#[derive(Debug)]
pub struct SshInput {
    rx: StreamReader<OkStream<mpsc::UnboundedReceiver<Bytes>>, Bytes>,
}

impl SshInput {
    pub(crate) fn new(rx: mpsc::UnboundedReceiver<Bytes>) -> Self {
        Self {
            rx: io::stream_reader(OkStream(rx)),
        }
    }
}

impl AsyncRead for SshInput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.rx).poll_read(cx, buf)
    }
}

fn into_io_error(error: mpsc::SendError) -> io::Error {
    if error.is_full() {
        io::Error::new(io::ErrorKind::Other, "resource busy")
    } else if error.is_disconnected() {
        io::ErrorKind::BrokenPipe.into()
    } else {
        io::Error::new(io::ErrorKind::Other, Box::new(error))
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ShutdownState {
    NeedsSend,
    NeedsFlush,
    NeedsClose,
    Done,
}

#[derive(Debug)]
pub struct SshOutput {
    channel: u32,
    tx: mpsc::UnboundedSender<Msg>,
    extended: Option<DataTypeCode>,
    shutdown_state: ShutdownState,
}

impl SshOutput {
    pub(crate) fn new(channel: u32, tx: mpsc::UnboundedSender<Msg>) -> Self {
        Self {
            channel,
            tx,
            extended: None,
            shutdown_state: ShutdownState::NeedsSend,
        }
    }

    pub(crate) fn with_extended(mut self, code: DataTypeCode) -> Self {
        self.extended = Some(code);
        self
    }
}

impl AsyncWrite for SshOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        ready!(Pin::new(&mut self.tx).poll_ready(cx)).map_err(into_io_error)?;

        let len = buf.len();
        let buf = buf.to_bytes();
        let msg = if let Some(code) = self.extended.clone() {
            ChannelExtendedData::new(self.channel, code, buf).into()
        } else {
            ChannelData::new(self.channel, buf).into()
        };
        Pin::new(&mut self.tx)
            .start_send(msg)
            .map_err(into_io_error)?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.tx).poll_flush(cx).map_err(into_io_error)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        ready!(Pin::new(&mut self.tx).poll_ready(cx)).map_err(into_io_error)?;

        loop {
            match self.shutdown_state {
                ShutdownState::NeedsSend => {
                    let msg = ChannelEof::new(self.channel).into();
                    Pin::new(&mut self.tx)
                        .start_send(msg)
                        .map_err(into_io_error)?;
                    self.shutdown_state = ShutdownState::NeedsFlush
                }

                ShutdownState::NeedsFlush => {
                    ready!(Pin::new(&mut self.tx).poll_flush(cx)).map_err(into_io_error)?;
                    self.shutdown_state = ShutdownState::NeedsClose
                }

                ShutdownState::NeedsClose => {
                    ready!(Pin::new(&mut self.tx).poll_close(cx)).map_err(into_io_error)?;
                    self.shutdown_state = ShutdownState::Done
                }

                ShutdownState::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

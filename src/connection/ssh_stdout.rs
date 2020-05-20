use std::error::Error as StdError;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Buf as _;
use futures::channel::mpsc::SendError;
use futures::ready;
use futures::sink::Sink;
use tokio::io::{self, AsyncWrite};

use crate::msg::{self, Msg};

pub trait IntoIoError: StdError {
    fn into_io_error(self) -> io::Error;
}

impl IntoIoError for SendError {
    fn into_io_error(self) -> io::Error {
        if self.is_full() {
            io::Error::new(io::ErrorKind::Other, "resource busy")
        } else if self.is_disconnected() {
            io::ErrorKind::BrokenPipe.into()
        } else {
            io::Error::new(io::ErrorKind::Other, Box::new(self))
        }
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
pub(crate) struct SshStdout<W, E> {
    channel: u32,
    inner: W,
    stdout: bool,
    shutdown_state: ShutdownState,
    _phantom: PhantomData<E>,
}

impl<W, E> SshStdout<W, E> {
    pub(crate) fn new(channel: u32, inner: W, stdout: bool) -> Self {
        Self {
            channel,
            inner,
            stdout,
            shutdown_state: ShutdownState::NeedsSend,
            _phantom: PhantomData,
        }
    }
}

impl<W, E> AsyncWrite for SshStdout<W, E>
where
    W: Sink<Msg, Error = E> + Unpin,
    E: IntoIoError + Unpin,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.inner).poll_ready(cx)).map_err(IntoIoError::into_io_error)?;

        let len = buf.len();
        let msg = if this.stdout {
            msg::channel_data::ChannelData::new(this.channel, (&mut buf).to_bytes()).into()
        } else {
            let t = msg::channel_extended_data::DataTypeCode::Stderr;
            msg::channel_extended_data::ChannelExtendedData::new(
                this.channel,
                t,
                (&mut buf).to_bytes(),
            )
            .into()
        };
        Pin::new(&mut this.inner)
            .start_send(msg)
            .map_err(IntoIoError::into_io_error)?;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.get_mut().inner)
            .poll_flush(cx)
            .map_err(IntoIoError::into_io_error)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.inner).poll_ready(cx)).map_err(IntoIoError::into_io_error)?;

        loop {
            match this.shutdown_state {
                ShutdownState::NeedsSend => {
                    let msg = msg::channel_eof::ChannelEof::new(this.channel).into();
                    Pin::new(&mut this.inner)
                        .start_send(msg)
                        .map_err(IntoIoError::into_io_error)?;
                    this.shutdown_state = ShutdownState::NeedsFlush;
                }
                ShutdownState::NeedsFlush => {
                    ready!(Pin::new(&mut this.inner)
                        .poll_flush(cx)
                        .map_err(IntoIoError::into_io_error))?;
                    this.shutdown_state = ShutdownState::NeedsClose;
                }
                ShutdownState::NeedsClose => {
                    ready!(Pin::new(&mut this.inner)
                        .poll_close(cx)
                        .map_err(IntoIoError::into_io_error))?;
                    this.shutdown_state = ShutdownState::Done;
                }
                ShutdownState::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::BytesMut;
use futures::ready;
use thiserror::Error;
use tokio::io::{self, AsyncBufReadExt as _, AsyncRead, AsyncWrite, BufStream};
use tokio::net::TcpStream;

use crate::handlers::Handlers;
use crate::preference::Preference;
use crate::stream::msg::MsgStream;
pub use run::RunError;

mod completion_stream;
mod run;
mod ssh_stdout;

#[derive(Debug, Error)]
pub enum AcceptError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("invalid version string")]
    InvalidVersion,

    #[error("unexpected eof")]
    UnexpectedEof,
}

/// Protocol Version Exchange
///
/// [rfc4253](https://tools.ietf.org/html/rfc4253#section-4.2)
#[derive(Debug)]
pub struct Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    io: Option<BufStream<IO>>,
    rxok: bool,
    rxbuf: Vec<u8>,
    txok: bool,
    txbuf: BytesMut,
    c_version: Option<String>,
    s_version: String,
    preference: Arc<Preference>,
}

impl<IO> Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(io: IO, preference: Arc<Preference>) -> Self {
        let s_version = format!("SSH-2.0-{}", preference.name());
        Accept {
            io: Some(BufStream::new(io)),
            rxok: false,
            rxbuf: Vec::new(),
            txok: false,
            txbuf: BytesMut::from(&*format!("{}\r\n", s_version)),
            c_version: None,
            s_version,
            preference,
        }
    }
}

#[derive(Debug)]
pub struct Established<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    io: MsgStream<IO>,
    c_version: String,
    s_version: String,
    preference: Arc<Preference>,
}

impl<IO> Established<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn new(
        io: BufStream<IO>,
        c_version: String,
        s_version: String,
        preference: Arc<Preference>,
    ) -> Self {
        Self {
            io: MsgStream::new(io),
            c_version,
            s_version,
            preference,
        }
    }
}

#[derive(Debug)]
pub struct Connection<S> {
    state: S,
}

impl Connection<Accept<TcpStream>> {
    pub fn remote_ip(&self) -> io::Result<SocketAddr> {
        self.state
            .io
            .as_ref()
            .expect("invalid state")
            .get_ref()
            .peer_addr()
    }
}

impl<IO> Connection<Accept<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(io: IO, preference: Arc<Preference>) -> Self {
        let state = Accept::new(io, preference);
        Self { state }
    }
}

impl<IO> Future for Connection<Accept<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<Connection<Established<IO>>, AcceptError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self { state } = self.get_mut();

        if !state.rxok {
            let mut task = state
                .io
                .as_mut()
                .expect("invalid state")
                .read_until(b'\n', &mut state.rxbuf);
            if matches!(Pin::new(&mut task).poll(cx)?, Poll::Ready(..)) {
                if state.rxbuf.is_empty() {
                    return Poll::Ready(Err(AcceptError::UnexpectedEof));
                }
                if !matches!(&state.rxbuf[..], [.., b'\r', b'\n']) {
                    return Poll::Ready(Err(AcceptError::InvalidVersion));
                }
                let version = String::from_utf8_lossy(&state.rxbuf[..state.rxbuf.len() - 2]);
                if !version.starts_with("SSH-2.0-") {
                    return Poll::Ready(Err(AcceptError::InvalidVersion));
                }
                state.c_version = Some(version.to_string());
                state.rxok = true
            }
        }

        if !state.txok {
            let mut io = state.io.as_mut().expect("invalid state");
            ready!(Pin::new(&mut io).poll_write_buf(cx, &mut state.txbuf)?);
            ready!(Pin::new(&mut io).poll_flush(cx)?);
            state.txok = true
        }

        if state.txok && state.rxok {
            Poll::Ready(Ok(Connection {
                state: Established::new(
                    state.io.take().unwrap(),
                    state.c_version.clone().unwrap(),
                    state.s_version.clone(),
                    state.preference.clone(),
                ),
            }))
        } else {
            Poll::Pending
        }
    }
}

impl<IO> Connection<Established<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub async fn run<H>(self, handler: H) -> Result<(), RunError>
    where
        H: Handlers,
    {
        let Established {
            io,
            c_version,
            s_version,
            preference,
        } = self.state;

        run::Runner::new(io, c_version, s_version, preference, handler)
            .run()
            .await
    }
}

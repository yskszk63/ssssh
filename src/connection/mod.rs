use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncWrite, BufStream};
use tokio::net::TcpStream;

use crate::handlers::Handlers;
use crate::preference::Preference;
use crate::stream::msg::MsgStream;
pub use run::RunError;

mod completion_stream;
mod run;
mod ssh_stdout;
mod version_ex;

#[derive(Debug, Error)]
pub enum AcceptError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("invalid version string: {0:?}")]
    InvalidVersion(String),

    #[error("unexpected eof {0:?}")]
    UnexpectedEof(BytesMut),
}

/// Protocol Version Exchange
///
/// [rfc4253](https://tools.ietf.org/html/rfc4253#section-4.2)
#[derive(Debug)]
pub struct Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    io: BufStream<IO>,
    preference: Arc<Preference>,
}

impl<IO> Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(io: IO, preference: Arc<Preference>) -> Self {
        Accept {
            io: BufStream::new(io),
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
        self.state.io.get_ref().peer_addr()
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

    pub async fn accept(self) -> Result<Connection<Established<IO>>, AcceptError> {
        let Accept { io, preference } = self.state;
        let (c_version, s_version, io) =
            version_ex::VersionExchange::new(io, preference.name().to_string()).await?;
        Ok(Connection {
            state: Established::new(io, c_version, s_version, preference),
        })
    }
}

impl<IO> Connection<Established<IO>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn client_version(&self) -> &str {
        &self.state.c_version
    }

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

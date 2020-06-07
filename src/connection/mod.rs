use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use crate::handlers::{HandlerError, Handlers};
use crate::preference::Preference;
use crate::stream::msg::MsgStream;
use crate::SshError;
pub use ssh_stream::{SshInput, SshOutput};

mod completion_stream;
mod run;
mod ssh_stream;
mod version_ex;

/// Protocol Version Exchange
///
/// [rfc4253](https://tools.ietf.org/html/rfc4253#section-4.2)
#[derive(Debug)]
pub struct Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    io: IO,
    preference: Arc<Preference>,
}

impl<IO> Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(io: IO, preference: Arc<Preference>) -> Self {
        Accept { io, preference }
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
    fn new(io: IO, c_version: String, s_version: String, preference: Arc<Preference>) -> Self {
        Self {
            io: MsgStream::new(io),
            c_version,
            s_version,
            preference,
        }
    }
}

/// SSH connection.
///
/// - `Connection<Accept>`: Before handshake (version exchange) SSH connection.
/// - `Connection<Established>`: After handshake SSH connection.
#[derive(Debug)]
pub struct Connection<S> {
    state: S,
}

impl Connection<Accept<TcpStream>> {
    /// Get remote IP address.
    pub fn remote_ip(&self) -> io::Result<SocketAddr> {
        self.state.io.peer_addr()
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

    ///! Performe SSH version exchange.
    pub async fn accept(self) -> Result<Connection<Established<IO>>, SshError> {
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

    ///! Run with [`ssssh::Handlers`]
    pub async fn run<E>(self, handler: Handlers<E>) -> Result<(), SshError>
    where
        E: Into<HandlerError> + Send + 'static,
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

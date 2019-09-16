use std::fmt::{Debug, Display};
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use failure::Fail;
use tokio::net::{TcpListener, TcpStream};

use crate::algorithm::Preference;
use crate::connection::Connection;
use crate::handler::Handler;
use crate::hostkey::{HostKey, HostKeys};
use crate::transport::version::VersionExchangeError;

#[derive(Debug, Fail)]
pub enum AcceptError<R>
where
    R: Debug + Display + Sync + Send + 'static,
{
    #[fail(display = "Empty Version {}", _0)]
    Empty(R),
    #[fail(display = "Invalid SSH identification string {}", _0)]
    InvalidFormat(R),
    #[fail(display = "Io Error {}", _1)]
    Io(Option<R>, #[fail(cause)] io::Error),
}

impl<R> AcceptError<R>
where
    R: Debug + Display + Sync + Send + 'static,
{
    pub fn remote(&self) -> Option<&R> {
        match self {
            Self::Empty(r) | Self::InvalidFormat(r) | Self::Io(Some(r), ..) => Some(r),
            Self::Io(None, ..) => None,
        }
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct ServerBuilder {
    version: Option<String>,
    preference: Option<Preference>,
    hostkeys: Option<HostKeys>,
    timeout: Option<Duration>,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self {
            version: None,
            preference: None,
            hostkeys: None,
            timeout: None,
        }
    }
}

impl ServerBuilder {
    pub fn version(mut self, v: impl Into<String>) -> Self {
        self.version = Some(v.into());
        self
    }
    pub fn preference(mut self, v: Preference) -> Self {
        self.preference = Some(v);
        self
    }
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
    pub async fn build<HF>(self, addr: SocketAddr, handler_factory: HF) -> io::Result<Server<HF>> {
        let socket = TcpListener::bind(addr).await?;
        Ok(Server {
            version: self.version.unwrap_or_else(|| "SSH-2.0-sssh".into()),
            addr,
            preference: self.preference.unwrap_or_default(),
            hostkeys: self.hostkeys.unwrap_or_else(|| {
                HostKeys::new(vec![
                    HostKey::gen_ssh_ed25519().unwrap(),
                    HostKey::gen_ssh_rsa(2048).unwrap(),
                ])
            }),
            timeout: self.timeout,
            socket,
            handler_factory,
        })
    }
}

#[derive(Debug)]
pub struct Server<HF> {
    version: String,
    addr: SocketAddr,
    preference: Preference,
    hostkeys: HostKeys,
    socket: TcpListener,
    timeout: Option<Duration>,
    handler_factory: HF,
}

impl<HF, H> Server<HF>
where
    H: Handler,
    HF: Fn() -> H,
{
    pub async fn accept(&mut self) -> Result<Connection<TcpStream, H>, AcceptError<SocketAddr>> {
        let (socket, remote) = self
            .socket
            .accept()
            .await
            .map_err(|e| AcceptError::Io(None, e))?;
        let result = Connection::establish(
            socket,
            self.version.clone(),
            remote,
            self.hostkeys.clone(),
            self.preference.clone(),
            self.timeout.clone(),
            (self.handler_factory)(),
        )
        .await
        .map_err(move |e| match e {
            VersionExchangeError::Io(e) => AcceptError::Io(Some(remote), e),
            VersionExchangeError::Empty => AcceptError::Empty(remote),
            VersionExchangeError::InvalidFormat => AcceptError::InvalidFormat(remote),
        })?;

        Ok(result)
    }
}

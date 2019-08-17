use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};

use crate::algorithm::Preference;
use crate::connection::Connection;
use crate::handler::{AuthHandler, ChannelHandler};
use crate::hostkey::{HostKey, HostKeys};

#[derive(Debug)]
pub struct ServerBuilder {
    version: Option<String>,
    preference: Option<Preference>,
    hostkeys: Option<HostKeys>,
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self {
            version: None,
            preference: None,
            hostkeys: None,
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
    pub fn build<AHF, CHF>(
        self,
        addr: SocketAddr,
        auth_handler_factory: AHF,
        channel_handler_factory: CHF,
    ) -> Server<AHF, CHF> {
        Server {
            version: self.version.unwrap_or("SSH-2.0-sssh".into()),
            addr,
            preference: self.preference.unwrap_or_default(),
            hostkeys: self
                .hostkeys
                .unwrap_or_else(|| HostKeys::new(vec![HostKey::gen_ssh_ed25519()])),
            socket: None,
            auth_handler_factory,
            channel_handler_factory,
        }
    }
}

#[derive(Debug)]
pub struct Server<AHF, CHF> {
    version: String,
    addr: SocketAddr,
    preference: Preference,
    hostkeys: HostKeys,
    socket: Option<TcpListener>,
    auth_handler_factory: AHF,
    channel_handler_factory: CHF,
}

impl<AHF, CHF, AH, CH> Server<AHF, CHF>
where
    AH: AuthHandler,
    CH: ChannelHandler,
    AHF: Fn() -> AH,
    CHF: Fn() -> CH,
{
    pub async fn accept(&mut self) -> Connection<TcpStream, SocketAddr, AH, CH> {
        if self.socket.is_none() {
            self.socket = Some(TcpListener::bind(&self.addr).unwrap());
        }

        let socket = self.socket.as_mut().unwrap();

        let (socket, remote) = socket.accept().await.unwrap();
        Connection::establish(
            socket,
            self.version.clone(),
            remote,
            self.hostkeys.clone(),
            self.preference.clone(),
            (self.auth_handler_factory)(),
            (self.channel_handler_factory)(),
        )
        .await
        .unwrap()
    }
}

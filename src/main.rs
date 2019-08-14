#![feature(async_await)]

use std::convert::TryFrom;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::pin::Pin;
use std::string::FromUtf8Error;

use bytes::{Bytes, BytesMut};
use futures::{Sink, SinkExt as _, StreamExt as _, TryStream, TryStreamExt};
use rand::SeedableRng as _;
use tokio::codec::{Decoder, Framed};
use tokio::net::{TcpListener, TcpStream};

use algorithm::{Algorithm, Preference};
use hostkey::{HostKey, HostKeys};
use msg::{Message, MessageError, MessageId, MessageResult};
use transport::codec::{Codec as TransportCodec, CodecError};
use transport::version::{exchange_version, VersionExchangeError};

mod algorithm;
mod compression;
mod encrypt;
mod hostkey;
mod kex;
mod mac;
mod msg;
mod named;
mod sshbuf;
mod transport;

fn decode(src: Bytes) -> Pin<Box<dyn Future<Output = MessageResult<Message>> + Send>> {
    Box::pin(async move { Message::try_from(src) })
}

fn encode(src: Message) -> Pin<Box<dyn Future<Output = MessageResult<Bytes>> + Send>> {
    Box::pin(async move {
        let mut buf = BytesMut::with_capacity(1024 * 8);
        src.put(&mut buf)?;
        Ok(buf.freeze())
    })
}

#[derive(Debug)]
pub enum ConnectionError {
    UnknownMessageId(u8),
    Unimplemented(MessageId),
    Underflow,
    Overflow,
    FromUtf8Error(FromUtf8Error),
    InvalidFormat,
    Io(io::Error),
}

impl From<io::Error> for ConnectionError {
    fn from(v: io::Error) -> Self {
        Self::Io(v)
    }
}

impl From<VersionExchangeError> for ConnectionError {
    fn from(v: VersionExchangeError) -> Self {
        match v {
            VersionExchangeError::Io(e) => Self::Io(e),
            VersionExchangeError::InvalidFormat => Self::InvalidFormat,
        }
    }
}

impl From<MessageError> for ConnectionError {
    fn from(v: MessageError) -> Self {
        match v {
            MessageError::FromUtf8Error(e) => Self::FromUtf8Error(e),
            MessageError::Unimplemented(e) => Self::Unimplemented(e),
            MessageError::Overflow => Self::Overflow,
            MessageError::Underflow => Self::Underflow,
            MessageError::UnknownMessageId(id) => Self::UnknownMessageId(id),
            MessageError::Codec(CodecError::Io(e)) => Self::Io(e),
        }
    }
}

#[derive(Debug)]
pub struct Connection<'a> {
    version: String,
    socket: TcpStream,
    hostkeys: &'a HostKeys,
    preference: &'a Preference,
}

impl<'a> Connection<'a> {
    fn new(
        version: String,
        socket: TcpStream,
        hostkeys: &'a HostKeys,
        preference: &'a Preference,
    ) -> Self {
        Connection {
            version,
            socket,
            hostkeys,
            preference,
        }
    }

    pub async fn run(self) {
        if let Err(e) = self.run0().await {
            eprintln!("ERR {:?}", e);
        }
    }

    async fn run0(mut self) -> Result<(), ConnectionError> {
        let server_version = self.version;
        let (cli_version, read_buf) =
            exchange_version(&mut self.socket, Bytes::from(server_version.clone())).await?;
        match &cli_version.get(..8) {
            Some(b"SSH-2.0-") => (),
            _ => return Err(VersionExchangeError::InvalidFormat.into()),
        }

        let rng = rand::rngs::StdRng::from_entropy();
        let mut parts = TransportCodec::new(rng)
            .framed(&mut self.socket)
            .into_parts();
        parts.read_buf = read_buf;
        let (tx, rx) = Framed::from_parts(parts).split();
        let mut tx = tx.with(encode);
        let mut rx = rx.err_into().and_then(decode);

        let (h, k, algorithm) = Self::kex(
            &mut tx,
            &mut rx,
            server_version.as_bytes(),
            &cli_version,
            &self.hostkeys,
            &self.preference,
        )
        .await?;

        let mut io = tx
            .into_inner()
            .reunite(rx.into_inner().into_inner())
            .unwrap();
        io.codec_mut().change_key(h, k, algorithm);
        let (tx, rx) = io.split();
        let mut tx = tx.with(encode);
        let mut rx = rx.err_into().and_then(decode);

        loop {
            let pkt = match rx.try_next().await? {
                Some(e) => e,
                None => break,
            };
            dbg!(&pkt);
            tx.send(pkt).await?;
        }

        Ok(())
    }

    async fn kex<T, R>(
        tx: &mut T,
        rx: &mut R,
        server_version: &[u8],
        client_version: &[u8],
        hostkeys: &HostKeys,
        preference: &Preference,
    ) -> Result<(Bytes, Bytes, Algorithm), ConnectionError>
    where
        R: TryStream<Ok = Message, Error = MessageError> + Unpin,
        T: Sink<Message, Error = MessageError> + Unpin,
    {
        let client_kexinit = if let Some(Message::Kexinit(e)) = rx.try_next().await? {
            e
        } else {
            panic!()
        };

        let server_kexinit = preference.to_kexinit();
        tx.send(server_kexinit.clone().into()).await?;
        let algorithm = Algorithm::negotiate(&client_kexinit, preference).unwrap();
        let hostkey = hostkeys
            .lookup(&algorithm.server_host_key_algorithm())
            .unwrap();

        let mut env = kex::KexEnv::new(
            tx,
            rx,
            client_version,
            server_version,
            &client_kexinit,
            &server_kexinit,
            hostkey,
        );
        let (h, k) = kex::kex(algorithm.kex_algorithm(), &mut env)
            .await
            .unwrap()
            .split();

        if let Some(Message::Newkeys(..)) = rx.try_next().await? {
            tx.send(msg::Newkeys.into()).await?;
        } else {
            panic!()
        };

        Ok((h, k, algorithm))
    }
}

#[derive(Debug)]
pub struct ServerConfig {
    version: String,
    addrs: Vec<SocketAddr>,
    hostkeys: HostKeys,
    preference: Preference,
}

impl ServerConfig {
    pub fn new(
        version: impl Into<String>,
        addrs: impl ToSocketAddrs,
        hostkeys: HostKeys,
        preference: Preference,
    ) -> io::Result<Self> {
        let version = version.into();
        let addrs = addrs.to_socket_addrs()?;
        let addrs = addrs.collect();
        Ok(ServerConfig {
            version,
            addrs,
            hostkeys,
            preference,
        })
    }
}

#[derive(Debug)]
pub struct Server {
    config: ServerConfig,
}

impl Server {
    pub fn with_config(config: ServerConfig) -> Self {
        Server { config }
    }

    pub async fn serve(&mut self) -> io::Result<()> {
        let mut listener = TcpListener::bind(self.config.addrs.iter().next().unwrap())?;
        //        loop {
        let (socket, _) = listener.accept().await?;
        let connection = Connection::new(
            self.config.version.clone(),
            socket,
            &self.config.hostkeys,
            &self.config.preference,
        );
        //            tokio::executor::spawn(connection.run());
        connection.run().await;
        //        }
        Ok(())
    }
}

#[tokio::main(single_thread)]
async fn main() {
    tokio::executor::spawn(async {
        use std::process::Command;
        use tokio_process::CommandExt as _;
        Command::new("ssh")
            .arg("-oStrictHostKeyChecking=no")
            .arg("-oUserKnownHostsFile=/dev/null")
            .arg("-p2222")
            .arg("-vvv")
            .arg("::1")
            //.stdout(std::process::Stdio::null())
            //.stderr(std::process::Stdio::null())
            .spawn_async()
            .unwrap()
            .await
            .unwrap();
    });

    let hostkey = HostKey::gen_ssh_ed25519();
    let hostkeys = HostKeys::new(vec![hostkey]);
    let conf =
        ServerConfig::new("SSH-2.0-ssh", "[::1]:2222", hostkeys, Preference::default()).unwrap();
    let mut server = Server::with_config(conf);
    server.serve().await.unwrap();
}

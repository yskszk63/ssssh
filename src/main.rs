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

use msg::{Kexinit, Message, MessageError, MessageId, MessageResult};
use transport::codec::{Codec as TransportCodec, CodecError};
use transport::version::{exchange_version, VersionExchangeError};

mod msg;
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
pub struct Connection {
    socket: TcpStream,
}

impl Connection {
    fn new(socket: TcpStream) -> Self {
        Connection { socket }
    }

    pub async fn run(self) {
        if let Err(e) = self.run0().await {
            eprintln!("ERR {:?}", e);
        }
    }

    async fn run0(mut self) -> Result<(), ConnectionError> {
        let server_version = "SSH-2.0-ssh";
        let (cli_version, read_buf) =
            exchange_version(&mut self.socket, Bytes::from(server_version)).await?;
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

        let (h, k) =
            Connection::kex(&mut tx, &mut rx, server_version.as_bytes(), &cli_version).await?;

        let mut io = tx
            .into_inner()
            .reunite(rx.into_inner().into_inner())
            .unwrap();
        io.codec_mut().change_key(h, k);
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
    ) -> Result<(Bytes, Bytes), ConnectionError>
    where
        R: TryStream<Ok = Message, Error = MessageError> + Unpin,
        T: Sink<Message, Error = MessageError> + Unpin,
    {
        let client_kexinit = if let Some(Message::Kexinit(e)) = rx.try_next().await? {
            e
        } else {
            panic!()
        };

        let server_kexinit = Kexinit::builder()
            .kex_algorithms(vec!["curve25519-sha256".into()])
            .server_host_key_algorithms(vec!["ssh-ed25519".into()])
            .encryption_algorithms_client_to_server(vec!["aes256-ctr".into()])
            .encryption_algorithms_server_to_client(vec!["aes256-ctr".into()])
            .mac_algorithms_client_to_server(vec!["hmac-sha2-256".into()])
            .mac_algorithms_server_to_client(vec!["hmac-sha2-256".into()])
            .compression_algorithms_client_to_server(vec!["none".into()])
            .compression_algorithms_server_to_client(vec!["none".into()])
            .build(client_kexinit.cookie());
        tx.send(server_kexinit.clone().into()).await?;

        let kex_edch_init = if let Some(Message::KexEdchInit(e)) = rx.try_next().await? {
            e
        } else {
            panic!()
        };

        use sodiumoxide::crypto::scalarmult::curve25519::SCALARBYTES;
        use sodiumoxide::crypto::scalarmult::curve25519::{
            scalarmult, scalarmult_base, GroupElement, Scalar,
        };

        let client_pubkey =
            GroupElement::from_slice(&kex_edch_init.ephemeral_public_key()).unwrap();
        let server_secret =
            Scalar::from_slice(&sodiumoxide::randombytes::randombytes(SCALARBYTES)).unwrap();
        let server_pubkey = scalarmult_base(&server_secret);
        let shared_key = scalarmult(&server_secret, &client_pubkey).unwrap();

        use sodiumoxide::crypto::sign::ed25519::gen_keypair;
        let (pubkey, secretkey) = gen_keypair();

        use sshbuf::SshBufMut as _;

        let mut s_kexinit = BytesMut::with_capacity(1024 * 8);
        let mut c_kexinit = BytesMut::with_capacity(1024 * 8);
        server_kexinit.put(&mut s_kexinit).unwrap();
        client_kexinit.put(&mut c_kexinit).unwrap();

        let mut buf = BytesMut::with_capacity(1024 * 8);
        buf.put_binary_string(client_version).unwrap();
        buf.put_binary_string(server_version).unwrap();
        buf.put_binary_string(&c_kexinit).unwrap();
        buf.put_binary_string(&s_kexinit).unwrap();
        buf.put_binary_string(&{
            let mut buf = BytesMut::with_capacity(1024 * 8);
            buf.put_string("ssh-ed25519").unwrap(); // xxxx
            buf.put_binary_string(&pubkey.0).unwrap();
            buf
        })
        .unwrap();
        buf.put_binary_string(&client_pubkey.0).unwrap();
        buf.put_binary_string(&server_pubkey.0).unwrap();
        buf.put_mpint(&shared_key.0).unwrap();

        let digest = sodiumoxide::crypto::hash::sha256::hash(&buf);
        let signature = sodiumoxide::crypto::sign::ed25519::sign_detached(&digest.0, &secretkey);

        tx.send(msg::KexEdchReply::new(&pubkey.0, &server_pubkey.0, &signature.0).into())
            .await?;

        if let Some(Message::Newkeys(..)) = rx.try_next().await? {
        } else {
            panic!()
        };
        tx.send(msg::Newkeys.into()).await?;

        Ok((Bytes::from(&digest.0[..]), Bytes::from(&shared_key.0[..])))
    }
}

#[derive(Debug)]
pub struct ServerConfig {
    addrs: Vec<SocketAddr>,
}

impl ServerConfig {
    pub fn with_addrs(self, addrs: impl ToSocketAddrs) -> io::Result<Self> {
        let addrs = addrs.to_socket_addrs()?;
        let addrs = addrs.collect();
        Ok(ServerConfig { addrs, ..self })
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            addrs: vec!["[::0]:22".parse().unwrap()],
        }
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
        let connection = Connection::new(socket);
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

    let mut server = Server::with_config(ServerConfig::default().with_addrs("[::1]:2222").unwrap());
    server.serve().await.unwrap();
}

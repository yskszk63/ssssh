use std::convert::TryFrom as _;
use std::error::Error as StdError;
use std::fmt::Display;
use std::io;
use std::pin::Pin;
use std::string::FromUtf8Error;
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use futures::future::Either;
use futures::stream::{select, Select, SplitSink, SplitStream};
use futures::{ready, Sink, SinkExt as _, Stream, StreamExt as _};
use rand::rngs::StdRng;
use rand::SeedableRng as _;
use tokio::codec::{Decoder as _, Framed};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::algorithm::{Algorithm, Preference};
use crate::handle::GlobalHandle;
use crate::handler::{Auth, AuthHandler, ChannelHandler};
use crate::hostkey::HostKeys;
use crate::kex::{kex, KexEnv};
use crate::msg::{self, Message, MessageError, MessageId, MessageResult};
use crate::transport::codec::{Codec, CodecError};
use crate::transport::version::{Version, VersionExchangeResult};

#[derive(Debug)]
enum MapEither<L, R> {
    Left(L),
    Right(R),
}

impl<L, R> MapEither<L, R> {
    fn get_left_mut(&mut self) -> Option<&mut L> {
        match self {
            Self::Left(ref mut e) => Some(e),
            Self::Right(..) => None,
        }
    }
    /*
    fn get_right_mut(&mut self) -> Option<&mut R> {
        match self {
            MapEither::Left(..) => None,
            MapEither::Right(ref mut e) => Some(e),
        }
    }
    */
}

impl<L, R> Stream for MapEither<L, R>
where
    L: Stream + Unpin,
    R: Stream + Unpin,
{
    type Item = Either<<L as Stream>::Item, <R as Stream>::Item>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            Self::Left(ref mut item) => Pin::new(item)
                .poll_next(cx)
                .map(|opt| opt.map(Either::Left)),
            Self::Right(ref mut item) => Pin::new(item)
                .poll_next(cx)
                .map(|opt| opt.map(Either::Right)),
        }
    }
}

#[derive(Debug)]
struct ChangeKeyRequest {
    hash: Bytes,
    key: Bytes,
    algorithm: Algorithm,
}

#[derive(Debug)]
struct Transport<IO> {
    rx: mpsc::Receiver<ChangeKeyRequest>,
    io: Framed<IO, Codec<StdRng>>,
}

impl<IO> Transport<IO> {
    fn new(io: Framed<IO, Codec<StdRng>>) -> (Self, mpsc::Sender<ChangeKeyRequest>) {
        let (tx, rx) = mpsc::channel(1);
        (Self { rx, io }, tx)
    }

    fn poll_change_key_if_needed(&mut self, cx: &mut Context) {
        if let Poll::Ready(Some(req)) = Pin::new(&mut self.rx).poll_next(cx) {
            self.io
                .codec_mut()
                .change_key(&req.hash, &req.key, &req.algorithm);
        };
    }
}

impl<IO> Stream for Transport<IO>
where
    IO: AsyncRead + Unpin,
{
    type Item = MessageResult<Message>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        self.poll_change_key_if_needed(cx);

        Pin::new(&mut self.io)
            .poll_next(cx)
            .map(|opt| opt.map(|v| Message::try_from(v?)))
    }
}

impl<IO> Sink<Message> for Transport<IO>
where
    IO: AsyncWrite + Unpin,
{
    type Error = MessageError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<MessageResult<()>> {
        self.poll_change_key_if_needed(cx);

        Poll::Ready(Ok(ready!(Pin::new(&mut self.io).poll_ready(cx))?))
    }

    fn start_send(mut self: Pin<&mut Self>, item: Message) -> MessageResult<()> {
        let mut buf = BytesMut::with_capacity(1024 * 8);
        item.put(&mut buf)?;
        Ok(Pin::new(&mut self.io).start_send(buf.freeze())?)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<MessageResult<()>> {
        self.poll_change_key_if_needed(cx);

        Poll::Ready(Ok(ready!(Pin::new(&mut self.io).poll_flush(cx))?))
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<MessageResult<()>> {
        self.poll_change_key_if_needed(cx);

        Poll::Ready(Ok(ready!(Pin::new(&mut self.io).poll_close(cx))?))
    }
}

#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub enum ConnectionError {
    UnknownMessageId(u8),
    Unimplemented(MessageId),
    Underflow,
    Overflow,
    FromUtf8Error(FromUtf8Error),
    AuthError(Box<dyn StdError + Send + Sync>),
    ChannelError(Box<dyn StdError + Send + Sync>),
    Io(io::Error),
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

#[allow(clippy::module_name_repetitions)]
pub type ConnectionResult<T> = Result<T, ConnectionError>;

type IncommingOrOutgoing<IO> = MapEither<SplitStream<Transport<IO>>, mpsc::Receiver<Message>>;

#[derive(Debug)]
pub struct Connection<IO, R, AH, CH>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    version: Version,
    rx: Select<IncommingOrOutgoing<IO>, IncommingOrOutgoing<IO>>,
    tx: SplitSink<Transport<IO>, Message>,
    remote: Option<R>,
    hostkeys: HostKeys,
    preference: Preference,
    auth_handler: AH,
    channel_handler: CH,
    change_key_send: mpsc::Sender<ChangeKeyRequest>,
    message_send: mpsc::Sender<Message>,
}

impl<IO, R, AH, CH> Connection<IO, R, AH, CH>
where
    IO: AsyncRead + AsyncWrite + Unpin,
    R: Display,
    AH: AuthHandler,
    CH: ChannelHandler,
{
    pub async fn establish(
        mut socket: IO,
        server_version: impl Into<Bytes>,
        remote: R,
        hostkeys: HostKeys,
        preference: Preference,
        auth_handler: AH,
        channel_handler: CH,
    ) -> VersionExchangeResult<Self> {
        let (version, rbuf) = Version::exchange(&mut socket, server_version).await?;

        let rng = StdRng::from_entropy();
        let mut parts = Codec::new(rng).framed(socket).into_parts();
        parts.read_buf = rbuf;

        let (message_send, message_recieve) = mpsc::channel(1);

        let io = Framed::from_parts(parts);
        let (io, change_key_send) = Transport::new(io);
        let (tx, rx) = io.split();
        let rx = select(MapEither::Left(rx), MapEither::Right(message_recieve));
        let remote = Some(remote);
        Ok(Self {
            version,
            rx,
            tx,
            remote,
            hostkeys,
            preference,
            auth_handler,
            channel_handler,
            change_key_send,
            message_send,
        })
    }

    async fn send(&mut self, item: impl Into<Message>) -> MessageResult<()> {
        self.message_send.send(item.into()).await.unwrap();
        Ok(())
    }

    pub async fn run(mut self) {
        if let Err(e) = &mut self.run0().await {
            eprintln!("{:?}", e);
            self.tx
                .send(msg::Disconnect::new(2, "unexpected", "").into())
                .await
                .ok(); // TODO
        }
    }

    async fn run0(&mut self) -> ConnectionResult<()> {
        use msg::Message::*;

        while let Some(m) = self.rx.next().await {
            match m {
                Either::Left(m) => match m? {
                    Kexinit(item) => self.on_kexinit(*item).await?,
                    ServiceRequest(item) => self.on_service_request(item).await?,
                    UserauthRequest(item) => self.on_userauth_request(item).await?,
                    ChannelOpen(item) => self.on_channel_open(item).await?,
                    ChannelRequest(item) => self.on_channel_request(item).await?,
                    ChannelData(item) => self.on_channel_data(item).await?,
                    ChannelClose(item) => self.on_channel_close(item).await?,
                    Ignore(..) => {}
                    Disconnect(item) => {
                        self.on_disconnect(item).await?;
                        break;
                    }
                    x => panic!("{:?}", x),
                },
                Either::Right(m) => {
                    self.tx.send(m).await?;
                }
            }
        }
        Ok(())
    }

    async fn on_kexinit(&mut self, client_kexinit: msg::Kexinit) -> ConnectionResult<()> {
        let server_kexinit = self.preference.to_kexinit();
        self.tx.send(server_kexinit.clone().into()).await?;

        let algorithm = Algorithm::negotiate(&client_kexinit, &self.preference).unwrap();
        let hostkey = self
            .hostkeys
            .lookup(&algorithm.server_host_key_algorithm())
            .unwrap();

        let (h, k) = {
            let mut env = KexEnv::new(
                &mut self.tx,
                self.rx.get_mut().0.get_left_mut().unwrap(),
                &self.version,
                &client_kexinit,
                &server_kexinit,
                hostkey,
            );
            kex(algorithm.kex_algorithm(), &mut env)
                .await
                .unwrap()
                .split()
        };

        if let Some(Either::Left(Ok(Message::Newkeys(..)))) = self.rx.next().await {
            self.tx.send(msg::Newkeys.into()).await?;
        } else {
            panic!()
        }
        self.change_key_send
            .send(ChangeKeyRequest {
                hash: h,
                key: k,
                algorithm,
            })
            .await
            .unwrap();

        Ok(())
    }

    async fn on_service_request(&mut self, msg: msg::ServiceRequest) -> ConnectionResult<()> {
        match msg.name() {
            "ssh-userauth" => self.send(msg::ServiceAccept::new(msg.name())).await?,
            _ => return Err(ConnectionError::Overflow), // TODO
        }
        Ok(())
    }

    async fn on_userauth_request(&mut self, msg: msg::UserauthRequest) -> ConnectionResult<()> {
        if msg.service_name() != "ssh-connection" {
            return Err(ConnectionError::Overflow); // TODO
        };

        let handle = GlobalHandle::new(self.message_send.clone()).new_auth_handle();
        let result = match msg.method_name() {
            "none" => self.auth_handler.handle_none(msg.user_name(), handle).await,
            "publickey" => {
                self.auth_handler
                    .handle_publickey(msg.user_name(), &[][..], handle)
                    .await // TODO
            }
            "password" => {
                self.auth_handler
                    .handle_password(msg.user_name(), &[][..], handle)
                    .await // TODO
            }
            _ => Ok(Auth::Reject),
        };

        let result = result.map_err(|e| ConnectionError::AuthError(e.into()))?;
        match result {
            Auth::Accept => self.send(msg::UserauthSuccess).await?,
            Auth::Reject => {
                self.send(msg::UserauthFailure::new(
                    vec!["publickey", "password"],
                    false,
                ))
                .await?
            }
        };
        Ok(())
    }

    async fn on_channel_open(&mut self, msg: msg::ChannelOpen) -> ConnectionResult<()> {
        match msg.channel_type() {
            "session" => {
                let handle = GlobalHandle::new(self.message_send.clone())
                    .new_channel_handle(msg.sender_channel());
                self.channel_handler
                    .handle_open_session(msg.sender_channel(), handle)
                    .await
            }
            _ => return Err(ConnectionError::Overflow), // TODO
        }
        .map_err(|e| ConnectionError::ChannelError(e.into()))?;

        let result = msg::ChannelOpenConfirmation::new(
            msg.sender_channel(),
            msg.sender_channel(),
            msg.initial_window_size(),
            msg.maximum_packet_size(),
        );
        self.send(result).await?;
        Ok(())
    }

    async fn on_channel_request(&mut self, msg: msg::ChannelRequest) -> ConnectionResult<()> {
        match msg.request_type() {
            "pty-req" => {
                let handle = GlobalHandle::new(self.message_send.clone())
                    .new_channel_handle(msg.recipient_channel());
                self.channel_handler
                    .handle_pty_request(msg.recipient_channel(), handle)
                    .await
            }
            "shell" => {
                let handle = GlobalHandle::new(self.message_send.clone())
                    .new_channel_handle(msg.recipient_channel());
                self.channel_handler
                    .handle_shell_request(msg.recipient_channel(), handle)
                    .await
            }
            x => {
                dbg!(x);
                return Err(ConnectionError::Overflow); // TODO
            }
        }
        .map_err(|e| ConnectionError::ChannelError(e.into()))?; // TODO channel failure

        self.send(msg::ChannelSuccess::new(msg.recipient_channel()))
            .await?;
        Ok(())
    }

    async fn on_channel_data(&mut self, msg: msg::ChannelData) -> ConnectionResult<()> {
        let handle = GlobalHandle::new(self.message_send.clone())
            .new_channel_handle(msg.recipient_channel());
        let r = self
            .channel_handler
            .handle_data(msg.recipient_channel(), &msg.data(), handle)
            .await;
        r.map_err(|e| ConnectionError::ChannelError(e.into()))?; // TODO
        Ok(())
    }

    async fn on_channel_close(&mut self, msg: msg::ChannelClose) -> ConnectionResult<()> {
        let handle = GlobalHandle::new(self.message_send.clone())
            .new_channel_handle(msg.recipient_channel());
        let r = self
            .channel_handler
            .handle_close(msg.recipient_channel(), handle)
            .await;
        r.map_err(|e| ConnectionError::ChannelError(e.into()))?; // TODO
        Ok(())
    }

    async fn on_disconnect(&mut self, _msg: msg::Disconnect) -> ConnectionResult<()> {
        // TODO
        Ok(())
    }
}

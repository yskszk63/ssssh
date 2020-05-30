use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use bytes::Bytes;
use futures::channel::mpsc;
use futures::future::Either;
use futures::future::TryFutureExt as _;
use futures::sink::SinkExt as _;
use futures::stream::Fuse;
use futures::stream::StreamExt as _;
use futures::stream::TryStreamExt as _;
use log::{debug, error, warn};
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::time;

use crate::handlers::{HandlerError, Handlers, PasswordResult};
use crate::msg::{self, Msg};
use crate::negotiate::negotiate;
use crate::preference::Preference;
use crate::stream::msg::MsgStream;
use crate::SshError;

use super::completion_stream::CompletionStream;
use super::ssh_stdout::SshStdout;

#[derive(Debug)]
enum Channel {
    Session(
        u32,
        Option<mpsc::UnboundedSender<Bytes>>,
        Option<Fuse<mpsc::UnboundedReceiver<Bytes>>>,
    ),
}

fn maybe_timeout(preference: &Preference) -> impl Future<Output = ()> {
    if let Some(timeout) = preference.timeout() {
        Either::Left(time::delay_for(*timeout))
    } else {
        Either::Right(futures::future::pending())
    }
}

#[derive(Debug)]
pub(super) struct Runner<IO, H>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handlers,
{
    io: MsgStream<IO>,
    c_version: String,
    s_version: String,
    preference: Arc<Preference>,
    handlers: H,
    channels: HashMap<u32, Channel>,
    outbound_channel_tx: mpsc::UnboundedSender<Msg>,
    outbound_channel_rx: Fuse<mpsc::UnboundedReceiver<Msg>>,
    completions: CompletionStream<Result<(), HandlerError>>,
    first_kexinit: Option<msg::kexinit::Kexinit>,
}

impl<IO, H> Runner<IO, H>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handlers,
{
    pub(super) fn new(
        io: MsgStream<IO>,
        c_version: String,
        s_version: String,
        preference: Arc<Preference>,
        handlers: H,
    ) -> Self {
        let (tx, rx) = mpsc::unbounded();
        let rx = rx.fuse();

        Self {
            io,
            c_version,
            s_version,
            preference,
            handlers,
            channels: Default::default(),
            outbound_channel_tx: tx,
            outbound_channel_rx: rx,
            completions: CompletionStream::new(),
            first_kexinit: None,
        }
    }

    async fn send<M: Into<Msg>>(&mut self, msg: M) -> Result<(), SshError> {
        self.io.send(msg.into()).await
    }

    pub(super) async fn run(&mut self) -> Result<(), SshError> {
        debug!("connection running...");
        let result = self.r#loop().await;
        if let Err(e) = &result {
            error!("error ocurred {}", e);
            let t = e
                .reason_code()
                .unwrap_or_else(|| msg::disconnect::ReasonCode::ProtocolError);
            let msg = msg::disconnect::Disconnect::new(t, "error occurred".into(), "".into());
            if let Err(e) = self.send(msg).await {
                error!("failed to send disconnect: {}", e)
            }
        }
        debug!("connection done.");
        result
    }

    async fn r#loop(&mut self) -> Result<(), SshError> {
        let first_kexinit = self.preference.to_kexinit();
        self.send(first_kexinit.clone()).await?;
        self.first_kexinit = Some(first_kexinit);

        let mut connected = true;

        while connected {
            let mut timeout = maybe_timeout(&self.preference);

            tokio::select! {
                Ok(msg) = self.io.try_next() => {
                    if let Some(msg) = msg {
                        self.handle_msg(&msg, &mut connected).await?;
                    } else {
                        connected = false;
                    }
                }
                Some(msg) = self.outbound_channel_rx.next() => self.send(msg).await?,
                Some(completed) = self.completions.next() => completed.map_err(SshError::HandlerError)?,
                _ = &mut timeout => {
                    let t = msg::disconnect::ReasonCode::ConnectionLost;
                    let msg = msg::disconnect::Disconnect::new(
                        t,
                        "timedout".into(),
                        "".into(),
                    );
                    if let Err(e) = self.send(msg).await {
                        warn!("failed to send disconnect: {}", e);
                    }
                    connected = false
                }
            }
        }
        Ok(())
    }

    async fn handle_msg(&mut self, msg: &msg::Msg, connected: &mut bool) -> Result<(), SshError> {
        match &msg {
            Msg::Kexinit(msg) => self.on_kexinit(msg).await?,
            Msg::ServiceRequest(msg) => self.on_service_request(msg).await?,
            Msg::UserauthRequest(msg) => self.on_userauth_request(msg).await?,
            Msg::GlobalRequest(msg) => self.on_global_request(msg).await?,
            Msg::ChannelOpen(msg) => self.on_channel_open(msg).await?,
            Msg::ChannelData(msg) => self.on_channel_data(msg).await?,
            Msg::ChannelEof(msg) => self.on_channel_eof(msg).await?,
            Msg::ChannelClose(msg) => self.on_channel_close(msg).await?,
            Msg::ChannelRequest(msg) => self.on_channel_request(msg).await?,
            Msg::Disconnect(..) => *connected = false,
            Msg::Ignore(..) => {}
            Msg::Unimplemented(..) => {}
            x => {
                warn!("UNHANDLED {:?}", x);

                let last_seq = self.io.get_ref().state().ctos().seq();
                let m = msg::unimplemented::Unimplemented::new(last_seq);
                self.send(m).await?;
            }
        }

        Ok(())
    }

    async fn on_kexinit(&mut self, kexinit: &msg::kexinit::Kexinit) -> Result<(), SshError> {
        use crate::kex::Kex;
        use crate::msg::new_keys::NewKeys;

        let c_kexinit = kexinit;
        let s_kexinit = if self.first_kexinit.is_some() {
            self.first_kexinit.take().unwrap()
        } else {
            let s_kexinit = self.preference.to_kexinit();
            self.send(s_kexinit.clone()).await?;
            s_kexinit
        };

        let algorithm = negotiate(&c_kexinit, &s_kexinit)?;
        debug!("algorithm: {:?}", algorithm);

        let hostkey = self
            .preference
            .hostkeys()
            .lookup(algorithm.server_host_key_algorithm())
            .unwrap();
        let kex = Kex::new(algorithm.kex_algorithm())?;

        debug!("Begin kex.. {:?}", kex);
        let (hash, key) = kex
            .kex(
                &mut self.io,
                &self.c_version,
                &self.s_version,
                &c_kexinit,
                &s_kexinit,
                hostkey,
            )
            .await?;
        debug!("Done kex. {:?}", kex);

        match self.io.try_next().await? {
            Some(Msg::NewKeys(..)) => {}
            Some(msg) => return Err(SshError::UnexpectedMsg(format!("{:?}", msg))),
            None => return Err(SshError::NoPacketReceived),
        };
        self.send(NewKeys::new()).await?;

        let state = self.io.get_mut().state_mut();
        state.change_key(&hash, &key, &kex, &algorithm)?;
        Ok(())
    }

    async fn on_service_request(
        &mut self,
        service_request: &msg::service_request::ServiceRequest,
    ) -> Result<(), SshError> {
        match service_request.service_name().as_ref() {
            name @ msg::service_request::SSH_USERAUTH => {
                let accept = msg::service_accept::ServiceAccept::new(name.into());
                self.send(accept).await?;
                Ok(())
            }
            msg::service_request::SSH_CONNECTION => {
                // TODO
                let reason = msg::disconnect::ReasonCode::HostNotAllowedToConnect;
                self.io
                    .send(msg::disconnect::Disconnect::new(reason, "".into(), "".into()).into())
                    .await?;
                Ok(())
            }
            _ => {
                // TODO
                let reason = msg::disconnect::ReasonCode::HostNotAllowedToConnect;
                self.io
                    .send(msg::disconnect::Disconnect::new(reason, "".into(), "".into()).into())
                    .await?;
                Ok(())
            }
        }
    }

    async fn on_userauth_request(
        &mut self,
        userauth_request: &msg::userauth_request::UserauthRequest,
    ) -> Result<(), SshError> {
        use msg::userauth_request::Method;

        let user_name = userauth_request.user_name();
        match userauth_request.method() {
            Method::None => {
                let r = self
                    .handlers
                    .handle_auth_none(user_name)
                    .await
                    .map_err(|e| SshError::HandlerError(e.into()))?;

                let m = if r {
                    msg::userauth_success::UserauthSuccess::new().into()
                } else {
                    msg::userauth_failure::UserauthFailure::new(
                        vec!["publickey", "password", "hostbased"]
                            .into_iter()
                            .collect(),
                        false,
                    )
                    .into()
                };
                self.send::<Msg>(m).await?;
            }

            Method::Publickey(item) if item.signature().is_none() => {
                use msg::UserauthPkMsg;
                let blob = item.blob().to_string();
                let r = self
                    .handlers
                    .handle_auth_publickey(user_name, item.algorithm(), &blob)
                    .await
                    .map_err(|e| SshError::HandlerError(e.into()))?;

                if r {
                    let m = msg::userauth_pk_ok::UserauthPkOk::new(
                        item.algorithm().into(),
                        item.blob().clone(),
                    )
                    .into();
                    self.io.context::<UserauthPkMsg>().send(m).await?;
                } else {
                    let m = msg::userauth_failure::UserauthFailure::new(
                        vec!["publickey", "password", "hostbased"]
                            .into_iter()
                            .collect(),
                        false,
                    );
                    self.send(m).await?;
                };
            }

            Method::Publickey(item) if item.signature().is_some() => {
                use crate::pack::Pack;
                use bytes::Buf as _;

                let signature = item.signature().as_ref().unwrap().clone();

                let pubkey = item.blob().clone();
                let mut verifier = pubkey.verifier()?;

                self.io
                    .get_ref()
                    .state()
                    .session_id()
                    .to_bytes()
                    .pack(&mut verifier);
                50u8.pack(&mut verifier);
                user_name.pack(&mut verifier);
                userauth_request.service_name().pack(&mut verifier);
                "publickey".pack(&mut verifier);
                true.pack(&mut verifier);
                item.algorithm().to_string().pack(&mut verifier);
                item.blob().pack(&mut verifier);

                let m = if verifier.verify(&signature) {
                    msg::userauth_success::UserauthSuccess::new().into()
                } else {
                    msg::userauth_failure::UserauthFailure::new(
                        vec!["publickey", "password", "hostbased"]
                            .into_iter()
                            .collect(),
                        false,
                    )
                    .into()
                };

                self.send::<Msg>(m).await?;
            }

            Method::Password(item) => {
                if let Some(newpassword) = item.newpassword() {
                    let r = self
                        .handlers
                        .handle_auth_password_change(user_name, item.password(), newpassword)
                        .await
                        .map_err(|e| SshError::HandlerError(e.into()))?;

                    let m = match r {
                        PasswordResult::Ok => msg::userauth_success::UserauthSuccess::new().into(),
                        PasswordResult::PasswordChangeRequired(message) => {
                            msg::userauth_passwd_changereq::UserauthPasswdChangereq::new(
                                message,
                                "".into(),
                            )
                            .into()
                        }
                        PasswordResult::Failure => msg::userauth_failure::UserauthFailure::new(
                            vec!["publickey", "password", "hostbased"]
                                .into_iter()
                                .collect(),
                            false,
                        )
                        .into(),
                    };
                    self.send::<Msg>(m).await?;
                } else {
                    let r = self
                        .handlers
                        .handle_auth_password(user_name, item.password())
                        .await
                        .map_err(|e| SshError::HandlerError(e.into()))?;
                    let m = match r {
                        PasswordResult::Ok => msg::userauth_success::UserauthSuccess::new().into(),
                        PasswordResult::PasswordChangeRequired(message) => {
                            msg::userauth_passwd_changereq::UserauthPasswdChangereq::new(
                                message,
                                "".into(),
                            )
                            .into()
                        }
                        PasswordResult::Failure => msg::userauth_failure::UserauthFailure::new(
                            vec!["publickey", "password", "hostbased"]
                                .into_iter()
                                .collect(),
                            false,
                        )
                        .into(),
                    };
                    self.send::<Msg>(m).await?;
                }
            }
            _ => {
                let r = msg::userauth_failure::UserauthFailure::new(
                    vec!["publickey", "password", "hostbased"]
                        .into_iter()
                        .collect(),
                    false,
                );
                self.send(r).await?;
            }
        }
        Ok(())
    }

    async fn on_channel_open(
        &mut self,
        channel_open: &msg::channel_open::ChannelOpen,
    ) -> Result<(), SshError> {
        use msg::channel_open::Type;

        let chid = *channel_open.sender_channel();
        match channel_open.typ() {
            Type::Session(..) => {
                let (stdin_tx, stdin_rx) = mpsc::unbounded();
                let stdin_rx = stdin_rx.fuse();

                let channel = Channel::Session(chid, Some(stdin_tx), Some(stdin_rx));
                self.channels.insert(chid, channel); // TODO check channel id

                let ok = msg::channel_open_confirmation::ChannelOpenConfirmation::new(
                    *channel_open.sender_channel(),
                    *channel_open.sender_channel(),
                    *channel_open.initial_window_size(),
                    *channel_open.maximum_packet_size(),
                    "".into(),
                );
                self.send(ok).await?;
                Ok(())
            }
            _ => {
                let ok = msg::channel_open_failure::ChannelOpenFailure::new(
                    *channel_open.sender_channel(),
                    msg::channel_open_failure::ReasonCode::UnknownChannelType,
                    "unknown channel".into(),
                    "en-US".into(),
                );
                self.send(ok).await?;
                Ok(())
            }
        }
    }

    async fn on_channel_data(
        &mut self,
        channel_data: &msg::channel_data::ChannelData,
    ) -> Result<(), SshError> {
        let chid = channel_data.recipient_channel();
        let data = channel_data.data();
        if let Some(channel) = self.channels.get_mut(chid) {
            match channel {
                Channel::Session(_, Some(stdin), _) => {
                    if stdin.is_closed() {
                        warn!("closed channel {}", chid);
                    } else {
                        stdin.send(data.clone()).await?;
                    }
                }
                _ => {} // FIXME
            }
        }
        Ok(())
    }

    async fn on_channel_eof(
        &mut self,
        channel_eof: &msg::channel_eof::ChannelEof,
    ) -> Result<(), SshError> {
        let chid = channel_eof.recipient_channel();
        if let Some(channel) = self.channels.get_mut(chid) {
            match channel {
                Channel::Session(_, stdin, _) => {
                    if let Some(stdin) = stdin.take() {
                        stdin.close_channel()
                    }
                }
            }
        }
        Ok(())
    }

    async fn on_channel_close(
        &mut self,
        channel_close: &msg::channel_close::ChannelClose,
    ) -> Result<(), SshError> {
        let chid = channel_close.recipient_channel();
        self.channels.remove(chid);
        Ok(())
    }

    async fn on_channel_request(
        &mut self,
        channel_request: &msg::channel_request::ChannelRequest,
    ) -> Result<(), SshError> {
        use msg::channel_request::Type;

        match channel_request.typ() {
            Type::Shell(..) => {
                let chid = channel_request.recipient_channel();
                if let Some(Channel::Session(_, _, stdin)) = self.channels.get_mut(chid) {
                    let stdin = io::stream_reader(stdin.take().unwrap().map(Ok));
                    let stdout = SshStdout::new(
                        *channel_request.recipient_channel(),
                        self.outbound_channel_tx.clone(),
                        true,
                    );
                    let stderr = SshStdout::new(
                        *channel_request.recipient_channel(),
                        self.outbound_channel_tx.clone(),
                        false,
                    );
                    let mut tx = self.outbound_channel_tx.clone();
                    let chid = *chid;
                    self.completions.push(
                        self.handlers
                            .handle_channel_shell(stdin, stdout, stderr)
                            .and_then(move |r| async move {
                                use msg::channel_close::ChannelClose;
                                use msg::channel_request::ChannelRequest;

                                let typ = Type::ExitStatus(r);
                                let msg = ChannelRequest::new(chid, false, typ).into();
                                tx.send(msg).await.ok(); // FIXME

                                let msg = ChannelClose::new(chid).into();
                                tx.send(msg).await.ok(); // FIXME

                                Ok(())
                            })
                            .map_err(Into::into),
                    );

                    let r = msg::channel_success::ChannelSuccess::new(
                        *channel_request.recipient_channel(),
                    );
                    self.send(r).await?;
                } else {
                    let r = msg::channel_failure::ChannelFailure::new(
                        *channel_request.recipient_channel(),
                    );
                    self.send(r).await?;
                }
            }
            Type::Exec(prog) => {
                let chid = channel_request.recipient_channel();
                if let Some(Channel::Session(_, _, stdin)) = self.channels.get_mut(chid) {
                    let stdin = io::stream_reader(stdin.take().unwrap().map(Ok));
                    let stdout = SshStdout::new(
                        *channel_request.recipient_channel(),
                        self.outbound_channel_tx.clone(),
                        true,
                    );
                    let stderr = SshStdout::new(
                        *channel_request.recipient_channel(),
                        self.outbound_channel_tx.clone(),
                        false,
                    );
                    let mut tx = self.outbound_channel_tx.clone();
                    let chid = *chid;
                    use std::os::unix::ffi::OsStringExt;
                    let prog = std::ffi::OsString::from_vec(prog.to_vec());
                    self.completions.push(
                        self.handlers
                            .handle_channel_exec(stdin, stdout, stderr, prog)
                            .and_then(move |r| async move {
                                use msg::channel_close::ChannelClose;
                                use msg::channel_request::ChannelRequest;

                                let typ = Type::ExitStatus(r);
                                let msg = ChannelRequest::new(chid, false, typ).into();
                                tx.send(msg).await.ok(); // FIXME

                                let msg = ChannelClose::new(chid).into();
                                tx.send(msg).await.ok(); // FIXME

                                Ok(())
                            })
                            .map_err(Into::into),
                    );

                    let r = msg::channel_success::ChannelSuccess::new(
                        *channel_request.recipient_channel(),
                    );
                    self.send(r).await?;
                } else {
                    let r = msg::channel_failure::ChannelFailure::new(
                        *channel_request.recipient_channel(),
                    );
                    self.send(r).await?;
                }
            }
            _ => {
                let r =
                    msg::channel_failure::ChannelFailure::new(*channel_request.recipient_channel());
                self.send(r).await?;
            }
        }
        Ok(())
    }

    async fn on_global_request(
        &mut self,
        global_request: &msg::global_request::GlobalRequest,
    ) -> Result<(), SshError> {
        use msg::global_request::Type;
        match global_request.typ() {
            Type::TcpipForward(..) => {
                let r = msg::request_success::RequestSuccess::new(vec![0x00].into());
                self.send(r).await?;
            }
            _ => {
                let r = msg::request_failure::RequestFailure::new();
                self.send(r).await?;
            }
        }
        Ok(())
    }
}

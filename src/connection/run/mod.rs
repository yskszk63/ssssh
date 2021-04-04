use std::pin::Pin;
use std::task::{Context, Poll};

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use futures::channel::{mpsc, oneshot};
use futures::future::{Either, TryFutureExt as _};
use futures::lock::Mutex;
use futures::sink::SinkExt as _;
use futures::stream::Stream;
use futures::stream::StreamExt as _;
use log::{debug, error, warn};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time;
use tokio_pipe::{PipeRead, PipeWrite};

use crate::handlers::{HandlerError, Handlers};
use crate::msg::channel_extended_data::DataTypeCode;
use crate::msg::{self, Msg};
use crate::preference::Preference;
use crate::stream::msg::MsgStream;
use crate::SshError;

use super::completion_stream::CompletionStream;
use super::reader_map::ReaderMap;
use super::ssh_stream::{SshInput, SshOutput};

mod on_channel_close;
mod on_channel_data;
mod on_channel_eof;
mod on_channel_open;
mod on_channel_request;
mod on_channel_window_adjust;
mod on_global_request;
mod on_kexinit;
mod on_service_request;
mod on_userauth_request;

type TaskStream = Arc<
    Mutex<
        CompletionStream<
            (u32, bool, Vec<oneshot::Receiver<()>>),
            Result<Option<u32>, HandlerError>,
        >,
    >,
>;

type OutputReaderMap = Arc<Mutex<ReaderMap<(u32, Option<DataTypeCode>), PipeRead>>>;

struct LockNext<'a, S> {
    inner: &'a mut S,
}

impl<'a, S> Future for LockNext<'a, Arc<Mutex<S>>>
where
    S: Stream + Unpin,
{
    type Output = Option<<S as Stream>::Item>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use std::ops::DerefMut;

        let mut item = match Pin::new(&mut self.get_mut().inner.lock()).poll(cx) {
            Poll::Ready(item) => item,
            Poll::Pending => return Poll::Pending,
        };
        match Pin::new(item.deref_mut()).poll_next(cx) {
            Poll::Ready(item) => Poll::Ready(item),
            Poll::Pending => Poll::Pending,
        }
    }
}

trait MutexStream: Sized {
    fn lock_next(&mut self) -> LockNext<Self>;
}

impl<S> MutexStream for Arc<Mutex<S>> {
    fn lock_next(&mut self) -> LockNext<Self> {
        LockNext { inner: self }
    }
}

#[derive(Debug)]
enum Channel {
    Session(u32, Option<PipeWrite>, Option<SshInput>),
    DirectTcpip(u32, Option<PipeWrite>),
}

fn maybe_timeout(preference: &Preference) -> impl Future<Output = ()> {
    if let Some(timeout) = preference.timeout() {
        Either::Left(time::sleep(*timeout))
    } else {
        Either::Right(futures::future::pending())
    }
}

#[derive(Debug)]
pub(super) struct Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    io: MsgStream<IO>,
    c_version: String,
    s_version: String,
    preference: Arc<Preference>,
    handlers: Handlers<E>,
    channels: HashMap<u32, Channel>,
    output_readers: OutputReaderMap,
    completions: TaskStream,
    msg_queue_tx: mpsc::UnboundedSender<Msg>,
    msg_queue_rx: mpsc::UnboundedReceiver<Msg>,
    first_kexinit: Option<msg::kexinit::Kexinit>,
    auth_state: on_userauth_request::AuthState,
}

impl<IO, E> Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) fn new(
        io: MsgStream<IO>,
        c_version: String,
        s_version: String,
        preference: Arc<Preference>,
        handlers: Handlers<E>,
    ) -> Self {
        let (msg_queue_tx, msg_queue_rx) = mpsc::unbounded();

        Self {
            io,
            c_version,
            s_version,
            preference,
            handlers,
            channels: Default::default(),
            output_readers: Arc::new(Mutex::new(ReaderMap::new())),
            completions: Arc::new(Mutex::new(CompletionStream::new())),
            msg_queue_tx,
            msg_queue_rx,
            first_kexinit: None,
            auth_state: on_userauth_request::AuthState::new(),
        }
    }

    async fn send<M: Into<Msg>>(&mut self, msg: M) -> Result<(), SshError> {
        self.io.send(msg.into()).await
    }

    async fn new_output(
        &mut self,
        channel: u32,
        type_code: Option<DataTypeCode>,
    ) -> Result<(SshOutput, oneshot::Receiver<()>), SshError> {
        let output_readers = self.output_readers.clone();
        let mut output_readers = output_readers.lock().await;

        let (r, w) = tokio_pipe::pipe()?;
        let output = SshOutput::new(w);
        debug!(
            "channel: {}, type: {:?} output: {:?} opened.",
            channel, &type_code, output
        );
        let closed = output_readers.insert((channel, type_code), r);

        Ok((output, closed))
    }

    async fn spawn_shell_handler<F, ERR>(
        &mut self,
        channel: u32,
        stdout_closed: oneshot::Receiver<()>,
        stderr_closed: oneshot::Receiver<()>,
        fut: F,
    ) where
        F: Future<Output = Result<u32, ERR>> + Send + 'static,
        ERR: Into<HandlerError>,
    {
        let completions = self.completions.clone();
        let mut completions = completions.lock().await;

        let fut = async move {
            debug!("spawn handler {}", channel);
            let r = fut.map_err(Into::into).await?;
            debug!("done spawn handler {}", channel);
            Ok::<_, HandlerError>(Some(r))
        };
        completions.push((channel, true, vec![stdout_closed, stderr_closed]), fut);
    }

    async fn spawn_handler<F, ERR>(
        &mut self,
        channel: u32,
        output_closed: oneshot::Receiver<()>,
        fut: F,
    ) where
        F: Future<Output = Result<(), ERR>> + Send + 'static,
        ERR: Into<HandlerError>,
    {
        let completions = self.completions.clone();
        let mut completions = completions.lock().await;

        let fut = async move {
            debug!("spawn handler {}", channel);
            fut.map_err(Into::into).await?;
            debug!("done spawn handler {}", channel);
            Ok(None)
        };
        completions.push((channel, true, vec![output_closed]), fut);
    }

    pub(super) async fn run(mut self) -> Result<(), SshError> {
        use msg::disconnect::{Disconnect, ReasonCode};

        debug!("connection running...");
        let result = self.r#loop().await;
        if let Err(e) = &result {
            error!("error ocurred {}", e);
            let t = e.reason_code().unwrap_or(ReasonCode::ProtocolError);
            let msg = Disconnect::new(t, "error occurred".into(), "".into());
            if let Err(e) = self.send(msg).await {
                error!("failed to send disconnect: {}", e)
            }
        }
        debug!("connection done.");
        self.io.close().await.ok();
        result
    }

    async fn r#loop(&mut self) -> Result<(), SshError> {
        let first_kexinit = self.preference.to_kexinit();
        self.send(first_kexinit.clone()).await?;
        self.first_kexinit = Some(first_kexinit);

        let reader = self.output_readers.clone();
        let tasks = self.completions.clone();
        let msg_queue_tx = self.msg_queue_tx.clone();

        tokio::select! {
            result = self.msg_loop() => result,
            result = Self::data_output_loop(reader, msg_queue_tx.clone()) => result,
            result = Self::task_loop(tasks, msg_queue_tx) => result,
        }
    }

    async fn msg_loop(&mut self) -> Result<(), SshError> {
        loop {
            let timeout = maybe_timeout(&self.preference);
            tokio::pin!(timeout);

            tokio::select! {
                msg = self.io.next() => {match msg {
                    Some(msg) => self.handle_msg(&msg?).await?,
                    None => return Ok(()),
                }}
                Some(msg) = self.msg_queue_rx.next() => self.send(msg).await?,
                _ = &mut timeout => return Err(SshError::Timeout)
            }
        }
    }

    async fn data_output_loop(
        mut read: OutputReaderMap,
        mut queue: mpsc::UnboundedSender<Msg>,
    ) -> Result<(), SshError> {
        use msg::channel_data::ChannelData;
        use msg::channel_extended_data::ChannelExtendedData;

        while let Some(result) = read.lock_next().await {
            let ((channel_id, type_code), buf) = result?;

            match (type_code, buf) {
                (Some(data_type), Some(buf)) => {
                    let msg = ChannelExtendedData::new(channel_id, data_type, buf).into();
                    queue.send(msg).await?;
                }
                (None, Some(buf)) => {
                    let msg = ChannelData::new(channel_id, buf).into();
                    queue.send(msg).await?;
                }
                (type_code, None) => {
                    debug!("channel: {}, type: {:?} reach eof.", channel_id, type_code)
                }
            };
        }
        Ok(())
    }

    async fn task_loop(
        mut tasks: TaskStream,
        mut queue: mpsc::UnboundedSender<Msg>,
    ) -> Result<(), SshError> {
        use msg::channel_close::ChannelClose;
        use msg::channel_eof::ChannelEof;
        use msg::channel_request::{ChannelRequest, Type};

        while let Some(completed) = tasks.lock_next().await {
            let ((channel_id, notify_status, output_closed), status) = completed;

            for f in output_closed {
                f.await.ok();
            }

            let msg = ChannelEof::new(channel_id).into();
            queue.send(msg).await?;

            if notify_status {
                let status = match status {
                    Ok(Some(status)) => status,
                    Err(_) | Ok(None) => 255,
                };
                let typ = Type::ExitStatus(status);
                let msg = ChannelRequest::new(channel_id, false, typ).into();
                queue.send(msg).await?;
            }

            let msg = ChannelClose::new(channel_id).into();
            queue.send(msg).await?;

            status.map_err(SshError::HandlerError)?;
        }
        Ok(())
    }

    async fn handle_msg(&mut self, msg: &msg::Msg) -> Result<(), SshError> {
        match &msg {
            Msg::Kexinit(msg) => self.on_kexinit(msg).await?,
            Msg::ServiceRequest(msg) => self.on_service_request(msg).await?,
            Msg::UserauthRequest(msg) => self.on_userauth_request(msg).await?,
            Msg::GlobalRequest(msg) => self.on_global_request(msg).await?,
            Msg::ChannelOpen(msg) => self.on_channel_open(msg).await?,
            Msg::ChannelData(msg) => self.on_channel_data(msg).await?,
            Msg::ChannelEof(msg) => self.on_channel_eof(msg).await?,
            Msg::ChannelClose(msg) => self.on_channel_close(msg).await?,
            Msg::ChannelWindowAdjust(msg) => self.on_channel_window_adjust(msg).await?,
            Msg::ChannelRequest(msg) => self.on_channel_request(msg).await?,
            Msg::Disconnect(..) => {}
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
}

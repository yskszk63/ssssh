use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::ready;
use thiserror::Error;
use tokio::io;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::stream::Stream;

use crate::preference::Preference;
use crate::{Accept, Connection};

#[derive(Debug, Error)]
pub enum BuildError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("unresolved")]
    Unresolved,
}

#[derive(Debug, Default)]
pub struct Builder {
    preference: Preference,
}

impl Builder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn timeout(&mut self, timeout: Duration) -> &mut Self {
        *self.preference.timeout_mut() = Some(timeout);
        self
    }

    pub async fn build<A>(mut self, addr: A) -> Result<Server<TcpListener, TcpStream>, BuildError>
    where
        A: ToSocketAddrs,
    {
        // FIXME
        (&mut self.preference)
            .hostkeys_mut()
            .insert(crate::hostkey::HostKey::gen("ssh-ed25519").unwrap());

        let addr = addr.to_socket_addrs().await?.next();
        if let Some(addr) = addr {
            let io = TcpListener::bind(addr).await?;
            let preference = Arc::new(self.preference);
            Ok(Server {
                io,
                preference,
                _stream: PhantomData,
            })
        } else {
            Err(BuildError::Unresolved)
        }
    }
}

#[derive(Debug)]
pub struct Server<L, S> {
    io: L,
    preference: Arc<Preference>,
    _stream: PhantomData<S>,
}

impl<L, S> Server<L, S>
where
    L: Stream<Item = io::Result<S>> + Unpin,
    S: io::AsyncRead + io::AsyncWrite + Unpin,
{
    pub fn builder() -> Builder {
        Builder::new()
    }
}

impl<L, S> Stream for Server<L, S>
where
    L: Stream<Item = io::Result<S>> + Unpin,
    S: io::AsyncRead + io::AsyncWrite + Unpin,
{
    type Item = io::Result<Connection<Accept<S>>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let result = ready!(Pin::new(&mut this.io).poll_next(cx));
        if let Some(stream) = result {
            Poll::Ready(Some(Ok(Connection::new(stream?, this.preference.clone()))))
        } else {
            Poll::Ready(None)
        }
    }
}

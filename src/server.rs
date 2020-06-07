use std::marker::PhantomData;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::ready;
use thiserror::Error;
use tokio::io;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::stream::Stream;

use crate::connection::{Accept, Connection};
use crate::preference::{Preference, PreferenceBuilder};
use crate::SshError;

#[derive(Debug, Error)]
pub enum BuildError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error("unresolved")]
    Unresolved,

    #[error(transparent)]
    SshError(#[from] SshError),
}

#[derive(Debug, Default)]
pub struct Builder {
    preference: PreferenceBuilder,
}

impl Builder {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn add_kex_algorithm(&mut self, name: crate::Kex) -> &mut Self {
        self.preference.add_kex_algorithm(name);
        self
    }

    pub fn add_encryption_algorithm(&mut self, name: crate::Cipher) -> &mut Self {
        self.preference.add_encryption_algorithm(name);
        self
    }

    pub fn add_mac_algorithm(&mut self, name: crate::Mac) -> &mut Self {
        self.preference.add_mac_algorithm(name);
        self
    }

    pub fn add_compression_algorithm(&mut self, name: crate::Compression) -> &mut Self {
        self.preference.add_compression_algorithm(name);
        self
    }

    pub fn name(&mut self, name: &str) -> &mut Self {
        self.preference.name(name);
        self
    }

    pub fn hostkeys_from_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.preference.hostkeys_from_dir(dir);
        self
    }

    pub fn hostkeys_from_path<P: AsRef<Path>>(&mut self, name: &str, file: P) -> &mut Self {
        self.preference.hostkeys_from_path(name, file);
        self
    }

    pub fn generate_hostkeys(&mut self) -> &mut Self {
        self.preference.hostkeys_generate();
        self
    }

    pub fn timeout(&mut self, timeout: Duration) -> &mut Self {
        self.preference.timeout(timeout);
        self
    }

    pub async fn build<A>(&self, addr: A) -> Result<Server<TcpListener, TcpStream>, BuildError>
    where
        A: ToSocketAddrs,
    {
        let preference = self.preference.build()?;
        let preference = Arc::new(preference);

        let addr = addr.to_socket_addrs().await?.next();
        if let Some(addr) = addr {
            let io = TcpListener::bind(addr).await?;
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

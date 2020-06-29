use std::hash::Hash;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, Bytes, BytesMut};
use futures::channel::oneshot;
use futures::stream::Stream;
use tokio::io::{self, AsyncRead};

#[derive(Debug)]
pub(crate) struct ReaderMap<K, V> {
    entries: Vec<(K, V, oneshot::Sender<()>)>,
    buf: BytesMut,
}

impl<K, V> ReaderMap<K, V> {
    pub(crate) fn new() -> Self {
        Self {
            entries: vec![],
            buf: BytesMut::with_capacity(8 * 1024),
        }
    }

    pub(crate) fn insert(&mut self, k: K, reader: V) -> oneshot::Receiver<()>
    where
        K: Hash + Eq,
    {
        let (tx, rx) = oneshot::channel();
        self.entries.push((k, reader, tx));
        rx
    }
}

impl<K, V> Stream for ReaderMap<K, V>
where
    K: Clone + Unpin,
    V: AsyncRead + Unpin,
{
    type Item = io::Result<(K, Option<Bytes>)>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut entries,
            ref mut buf,
        } = self.get_mut();

        for n in 0..entries.len() {
            let (k, reader, _) = &mut entries[n];
            buf.clear();

            match Pin::new(reader).poll_read_buf(cx, buf) {
                Poll::Ready(Ok(0)) => {
                    let (k, _, close_notify) = entries.swap_remove(n);
                    close_notify.send(()).ok();
                    return Poll::Ready(Some(Ok((k, None))));
                }
                Poll::Ready(Ok(n)) => {
                    return Poll::Ready(Some(Ok((k.clone(), Some((&buf[..n]).to_bytes())))))
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
                Poll::Pending => {}
            }
        }

        Poll::Pending
    }
}

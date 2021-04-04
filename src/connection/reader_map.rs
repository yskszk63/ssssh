use std::hash::Hash;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut as _, Bytes, BytesMut};
use futures::channel::oneshot;
use futures::stream::Stream;
use tokio::io::{self, AsyncRead, ReadBuf};

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

            let dst = buf.chunk_mut();
            let dst = unsafe { &mut *(dst as *mut _ as *mut [MaybeUninit<u8>]) };
            let mut buf = ReadBuf::uninit(dst);
            match Pin::new(reader).poll_read(cx, &mut buf)? {
                Poll::Ready(()) => {
                    if buf.filled().is_empty() {
                        let (k, _, close_notify) = entries.swap_remove(n);
                        close_notify.send(()).ok();
                        return Poll::Ready(Some(Ok((k, None))));
                    } else {
                        let buf = buf.filled();
                        return Poll::Ready(Some(Ok((
                            k.clone(),
                            Some(Bytes::copy_from_slice(buf)),
                        ))));
                    }
                }
                Poll::Pending => {}
            }
        }

        Poll::Pending
    }
}

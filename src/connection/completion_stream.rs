use std::fmt;
use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures::stream::Stream;
use tokio::sync::Notify;

pub(crate) struct CompletionStream<O> {
    tasks: Vec<Pin<Box<dyn Future<Output = O> + Send + 'static>>>,
    waker: Notify,
}

impl<O> fmt::Debug for CompletionStream<O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompletionStream")
    }
}

impl<O> CompletionStream<O> {
    pub(crate) fn new() -> Self {
        Self {
            tasks: Default::default(),
            waker: Default::default(),
        }
    }

    pub(crate) fn push<F>(&mut self, task: F)
    where
        F: Future<Output = O> + Send + 'static,
    {
        self.tasks.push(Box::pin(task));
        self.waker.notify();
    }
}

impl<O> Stream for CompletionStream<O> {
    type Item = O;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<O>> {
        let mut cur = vec![];
        mem::swap(&mut cur, &mut self.tasks);

        let mut ready = None;
        for mut task in cur {
            match Pin::new(&mut task).poll(cx) {
                Poll::Ready(x) if ready.is_none() => ready = Some(x),
                _ => self.tasks.push(task),
            }
        }

        if ready.is_some() {
            Poll::Ready(ready)
        } else {
            let _ = Box::pin(self.waker.notified()).as_mut().poll(cx);
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        fn assert<T>(_: T)
        where
            T: Send + 'static,
        {
        }

        assert(CompletionStream::<()>::new());
    }
}

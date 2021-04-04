use std::fmt;
use std::future::Future;
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use futures::future::BoxFuture;
use futures::stream::Stream;

pub(crate) struct CompletionStream<A, O> {
    tasks: Vec<(A, BoxFuture<'static, O>)>,
    waker: Option<Waker>,
}

impl<A, O> fmt::Debug for CompletionStream<A, O> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompletionStream")
    }
}

impl<A, O> CompletionStream<A, O> {
    pub(crate) fn new() -> Self {
        Self {
            tasks: Default::default(),
            waker: Default::default(),
        }
    }

    pub(crate) fn push<F>(&mut self, attachment: A, task: F)
    where
        F: Future<Output = O> + Send + 'static,
    {
        self.tasks.push((attachment, Box::pin(task)));
        if let Some(waker) = self.waker.take() {
            waker.wake();
        }
    }
}

impl<A, O> Stream for CompletionStream<A, O>
where
    A: Unpin,
    O: Unpin,
{
    type Item = (A, O);

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut tasks,
            ref mut waker,
        } = self.get_mut();

        let mut cur = vec![];
        mem::swap(&mut cur, tasks);

        let mut result = None;
        for (attachment, mut task) in cur {
            if result.is_none() {
                match Pin::new(&mut task).poll(cx) {
                    Poll::Ready(x) => result = Some((attachment, x)),
                    _ => tasks.push((attachment, task)),
                }
            } else {
                tasks.push((attachment, task))
            }
        }

        if let Some(result) = result {
            Poll::Ready(Some(result))
        } else {
            *waker = Some(cx.waker().clone());
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

        assert(CompletionStream::<(), ()>::new());
    }
}

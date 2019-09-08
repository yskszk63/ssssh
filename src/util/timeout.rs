use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::{ready, Stream};
use tokio::timer::timeout::{Elapsed, Timeout as TokioTimeout};

#[derive(Debug)]
pub(crate) enum Timeout<F>
where
    F: Stream,
{
    Some(TokioTimeout<F>),
    None(F),
}

impl<F> Timeout<F>
where
    F: Stream,
{
    pub(crate) fn new(val: F, delay: Option<Duration>) -> Self {
        match delay {
            Some(delay) => Self::Some(TokioTimeout::new(val, delay)),
            None => Self::None(val),
        }
    }

    /*
    pub(crate) fn get_ref(&self) -> &F {
        match self {
            Self::Some(v) => v.get_ref(),
            Self::None(v) => v
        }
    }
    */

    pub(crate) fn get_mut(&mut self) -> &mut F {
        match self {
            Self::Some(v) => v.get_mut(),
            Self::None(v) => v,
        }
    }

    /*
    pub(crate) fn into_inner(self) -> F {
        match self {
            Self::Some(v) => v.into_inner(),
            Self::None(v) => v
        }
    }
    */
}

impl<F> Stream for Timeout<F>
where
    F: Stream + Unpin,
{
    type Item = Result<F::Item, Elapsed>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.get_mut() {
            Self::Some(t) => Pin::new(t).poll_next(cx),
            Self::None(f) => match ready!(Pin::new(f).poll_next(cx)) {
                Some(e) => Poll::Ready(Some(Ok(e))),
                None => Poll::Ready(None),
            },
        }
    }
}

use std::pin::Pin;
use std::task::{Context, Poll};

use futures::future::Either;
use futures::Stream;

#[derive(Debug)]
pub(crate) enum MapEither<L, R> {
    Left(L),
    Right(R),
}

impl<L, R> MapEither<L, R> {
    pub(crate) fn get_left_mut_unchecked(&mut self) -> &mut L {
        match self {
            Self::Left(ref mut e) => e,
            Self::Right(..) => panic!(),
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

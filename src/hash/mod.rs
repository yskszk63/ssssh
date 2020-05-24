use bytes::{Buf, Bytes};

use crate::pack::Put;

mod sha;

trait HasherTrait: Put + Sized {
    fn new() -> Self;

    fn finish(self) -> Bytes;
}

#[derive(Debug)]
pub(crate) enum Hasher {
    Sha1(sha::Sha1),
    Sha256(sha::Sha256),
}

impl Hasher {
    pub(crate) fn sha1() -> Self {
        Self::Sha1(sha::Sha1::new())
    }

    pub(crate) fn sha256() -> Self {
        Self::Sha256(sha::Sha256::new())
    }

    pub(crate) fn finish(self) -> Bytes {
        match self {
            Self::Sha1(item) => item.finish(),
            Self::Sha256(item) => item.finish(),
        }
    }
}

impl Put for Hasher {
    fn put(&mut self, src: &[u8]) {
        match self {
            Self::Sha1(item) => item.put(src),
            Self::Sha256(item) => item.put(src),
        }
    }
}

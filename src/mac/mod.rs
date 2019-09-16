use bytes::Bytes;

use crate::algorithm::MacAlgorithm;

mod none;
mod sha;

pub(crate) enum Mac {
    None(none::NoneMac),
    HmacSha1(sha::HmacSha1),
    HmacSha2_256(sha::HmacSha2_256),
}

impl Mac {
    pub(crate) fn new(alg: &MacAlgorithm, key: &Bytes) -> Self {
        match alg {
            MacAlgorithm::HmacSha1 => Self::HmacSha1(sha::HmacSha1::new(key)),
            MacAlgorithm::HmacSha2_256 => Self::HmacSha2_256(sha::HmacSha2_256::new(key)),
        }
    }

    pub(crate) fn new_none() -> Self {
        Self::None(none::NoneMac)
    }

    pub(crate) fn size(&self) -> usize {
        match self {
            Self::None(m) => m.size(),
            Self::HmacSha1(m) => m.size(),
            Self::HmacSha2_256(m) => m.size(),
        }
    }

    /*
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Self::None(m) => m.name(),
            Self::HmacSha2_256(m) => m.name(),
        }
    }
    */

    pub(crate) fn sign(&self, seq: u32, plain: &Bytes, encrypted: &Bytes) -> Bytes {
        match self {
            Self::None(m) => m.sign(seq, plain, encrypted),
            Self::HmacSha1(m) => m.sign(seq, plain, encrypted),
            Self::HmacSha2_256(m) => m.sign(seq, plain, encrypted),
        }
    }
}

pub(crate) trait MacType {
    fn size(&self) -> usize;
    fn name(&self) -> &'static str;
    fn sign(&self, seq: u32, plain: &Bytes, encrypted: &Bytes) -> Bytes;
}

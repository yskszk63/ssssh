use std::str::FromStr;

use bytes::Bytes;

use crate::negotiate::{AlgorithmName, UnknownNameError};
use crate::SshError;

mod none;
mod sha;

/// SSH mac algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Algorithm {
    /// `none`
    None,

    /// `hmac-sha2-256`
    HmacSha256,

    /// `hmac-sha1`
    HmacSha1,
}

impl AsRef<str> for Algorithm {
    fn as_ref(&self) -> &str {
        match self {
            Self::None => "none",
            Self::HmacSha256 => "hmac-sha2-256",
            Self::HmacSha1 => "hmac-sha1",
        }
    }
}

impl FromStr for Algorithm {
    type Err = UnknownNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(Self::None),
            "hmac-sha2-256" => Ok(Self::HmacSha256),
            "hmac-sha1" => Ok(Self::HmacSha1),
            x => Err(UnknownNameError(x.into())),
        }
    }
}

impl AlgorithmName for Algorithm {
    fn defaults() -> Vec<Self> {
        vec![Self::HmacSha256, Self::HmacSha1]
    }
}

pub(crate) trait MacTrait: Into<Mac> + Sized {
    const NAME: Algorithm;
    const LEN: usize;
    fn new(key: &[u8]) -> Self;
    fn sign(&self, seq: u32, plain: &[u8]) -> Result<Bytes, SshError>;
    fn verify(&self, seq: u32, plain: &[u8], tag: &[u8]) -> Result<(), SshError>;
}

#[derive(Debug)]
pub(crate) enum Mac {
    None(none::None),
    HmacSha256(sha::HmacSha256),
    HmacSha1(sha::HmacSha1),
}

impl Mac {
    pub(crate) fn new_none() -> Self {
        none::None {}.into()
    }

    pub(crate) fn new(name: &Algorithm, key: &[u8]) -> Self {
        match name {
            Algorithm::None => none::None::new(key).into(),
            Algorithm::HmacSha256 => sha::HmacSha256::new(key).into(),
            Algorithm::HmacSha1 => sha::HmacSha1::new(key).into(),
        }
    }

    pub(crate) fn len_by_name(name: &Algorithm) -> usize {
        match name {
            Algorithm::None => none::None::LEN,
            Algorithm::HmacSha256 => sha::HmacSha256::LEN,
            Algorithm::HmacSha1 => sha::HmacSha1::LEN,
        }
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::None(..) => none::None::LEN,
            Self::HmacSha256(..) => sha::HmacSha256::LEN,
            Self::HmacSha1(..) => sha::HmacSha1::LEN,
        }
    }

    pub(crate) fn sign(&self, seq: u32, plain: &[u8]) -> Result<Bytes, SshError> {
        match self {
            Self::None(item) => item.sign(seq, plain),
            Self::HmacSha256(item) => item.sign(seq, plain),
            Self::HmacSha1(item) => item.sign(seq, plain),
        }
    }

    pub(crate) fn verify(
        &self,
        seq: u32,
        plain: &[u8],
        tag: &[u8],
    ) -> Result<(), SshError> {
        match self {
            Self::None(item) => item.verify(seq, plain, tag),
            Self::HmacSha256(item) => item.verify(seq, plain, tag),
            Self::HmacSha1(item) => item.verify(seq, plain, tag),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<Mac>();
    }

    #[test]
    fn test_none() {
        let name = &Algorithm::None;

        let k = Bytes::from(vec![0; Mac::len_by_name(name)]);

        let src = BytesMut::from("Hello, world!");
        let tag = Mac::new(name, &k).sign(0, &src).unwrap();
        Mac::new(name, &k).verify(0, &src, &tag).unwrap();

        Mac::new_none();
    }

    #[test]
    fn test_hmac_sha2_256() {
        let name = &Algorithm::HmacSha256;

        let k = Bytes::from(vec![0; Mac::len_by_name(name)]);

        let src = BytesMut::from("Hello, world!");
        let tag = Mac::new(name, &k).sign(0, &src).unwrap();
        Mac::new(name, &k).verify(0, &src, &tag).unwrap();

        Mac::new_none();
    }

    #[test]
    fn test_hmac_sha1() {
        let name = &Algorithm::HmacSha1;

        let k = Bytes::from(vec![0; Mac::len_by_name(name)]);

        let src = BytesMut::from("Hello, world!");
        let tag = Mac::new(name, &k).sign(0, &src).unwrap();
        Mac::new(name, &k).verify(0, &src, &tag).unwrap();

        Mac::new_none();
    }

    #[test]
    fn test_parse() {
        for name in Algorithm::defaults() {
            let s = name.as_ref();
            let a = Algorithm::from_str(s).unwrap();
            assert_eq!(name, a);
        }

        assert_eq!(Algorithm::None, Algorithm::from_str("none").unwrap());
        Algorithm::from_str("").unwrap_err();
    }
}

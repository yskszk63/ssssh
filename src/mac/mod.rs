use bytes::Bytes;

use crate::SshError;

mod none;
mod sha;

pub(crate) trait MacTrait: Into<Mac> + Sized {
    const NAME: &'static str;
    const LEN: usize;
    fn new(key: &[u8]) -> Self;
    fn sign(&self, seq: u32, plain: &[u8], encrypted: &[u8]) -> Result<Bytes, SshError>;
    fn verify(&self, seq: u32, plain: &[u8], encrypted: &[u8], tag: &[u8]) -> Result<(), SshError>;
}

#[derive(Debug)]
pub(crate) enum Mac {
    None(none::None),
    HmacSha256(sha::HmacSha256),
    HmacSha1(sha::HmacSha1),
}

impl Mac {
    pub(crate) fn defaults() -> Vec<String> {
        vec![
            sha::HmacSha256::NAME.to_string(),
            sha::HmacSha1::NAME.to_string(),
        ]
    }

    pub(crate) fn new_none() -> Self {
        none::None {}.into()
    }

    pub(crate) fn new(name: &str, key: &[u8]) -> Result<Self, SshError> {
        Ok(match name {
            none::None::NAME => none::None::new(key).into(),
            sha::HmacSha256::NAME => sha::HmacSha256::new(key).into(),
            sha::HmacSha1::NAME => sha::HmacSha1::new(key).into(),
            x => return Err(SshError::UnknownAlgorithm(x.to_string())),
        })
    }

    pub(crate) fn len_by_name(name: &str) -> Result<usize, SshError> {
        Ok(match name {
            none::None::NAME => none::None::LEN,
            sha::HmacSha256::NAME => sha::HmacSha256::LEN,
            sha::HmacSha1::NAME => sha::HmacSha1::LEN,
            x => return Err(SshError::UnknownAlgorithm(x.into())),
        })
    }

    pub(crate) fn len(&self) -> usize {
        match self {
            Self::None(..) => none::None::LEN,
            Self::HmacSha256(..) => sha::HmacSha256::LEN,
            Self::HmacSha1(..) => sha::HmacSha1::LEN,
        }
    }

    pub(crate) fn sign(&self, seq: u32, plain: &[u8], encrypted: &[u8]) -> Result<Bytes, SshError> {
        match self {
            Self::None(item) => item.sign(seq, plain, encrypted),
            Self::HmacSha256(item) => item.sign(seq, plain, encrypted),
            Self::HmacSha1(item) => item.sign(seq, plain, encrypted),
        }
    }

    pub(crate) fn verify(
        &self,
        seq: u32,
        plain: &[u8],
        encrypted: &[u8],
        tag: &[u8],
    ) -> Result<(), SshError> {
        match self {
            Self::None(item) => item.verify(seq, plain, encrypted, tag),
            Self::HmacSha256(item) => item.verify(seq, plain, encrypted, tag),
            Self::HmacSha1(item) => item.verify(seq, plain, encrypted, tag),
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
    fn test_unknown() {
        let k = Bytes::from("");
        Mac::new("-", &k).unwrap_err();
    }

    #[test]
    fn test_none() {
        let name = "none";

        let k = Bytes::from(vec![0; Mac::len_by_name(name).unwrap()]);

        let src = BytesMut::from("Hello, world!");
        let tag = Mac::new(name, &k).unwrap().sign(0, &src, &src).unwrap();
        Mac::new(name, &k)
            .unwrap()
            .verify(0, &src, &src, &tag)
            .unwrap();

        Mac::new_none();
    }

    #[test]
    fn test_hmac_sha2_256() {
        let name = "hmac-sha2-256";

        let k = Bytes::from(vec![0; Mac::len_by_name(name).unwrap()]);

        let src = BytesMut::from("Hello, world!");
        let tag = Mac::new(name, &k).unwrap().sign(0, &src, &src).unwrap();
        Mac::new(name, &k)
            .unwrap()
            .verify(0, &src, &src, &tag)
            .unwrap();

        Mac::new_none();
    }

    #[test]
    fn test_hmac_sha1() {
        let name = "hmac-sha1";

        let k = Bytes::from(vec![0; Mac::len_by_name(name).unwrap()]);

        let src = BytesMut::from("Hello, world!");
        let tag = Mac::new(name, &k).unwrap().sign(0, &src, &src).unwrap();
        Mac::new(name, &k)
            .unwrap()
            .verify(0, &src, &src, &tag)
            .unwrap();

        Mac::new_none();
    }
}

use std::iter::FromIterator;
use std::string::FromUtf8Error;

use bytes::buf::{Buf, BufExt as _};
use bytes::{Bytes, BytesMut};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UnpackError {
    #[error("unexpected eof")]
    UnexpectedEof,

    #[error(transparent)]
    FromUtf8Error(#[from] FromUtf8Error),
}

pub(crate) trait Put {
    fn put(&mut self, src: &[u8]);
}

impl Put for BytesMut {
    fn put(&mut self, src: &[u8]) {
        self.extend_from_slice(src);
    }
}

pub(crate) trait Pack {
    fn pack<P: Put>(&self, buf: &mut P);
}

pub(crate) trait Unpack: Sized {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError>;
}

impl Pack for bool {
    fn pack<P: Put>(&self, buf: &mut P) {
        (if *self { 1u8 } else { 0u8 }).pack(buf);
    }
}

impl Unpack for bool {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        Ok(u8::unpack(buf)? != 0)
    }
}

impl Pack for u8 {
    fn pack<P: Put>(&self, buf: &mut P) {
        buf.put(&[*self]);
    }
}

impl Unpack for u8 {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        if buf.remaining() < 1 {
            return Err(UnpackError::UnexpectedEof);
        }

        Ok(buf.get_u8())
    }
}

impl Pack for u32 {
    fn pack<P: Put>(&self, buf: &mut P) {
        buf.put(&self.to_be_bytes());
    }
}

impl Unpack for u32 {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        if buf.remaining() < 4 {
            return Err(UnpackError::UnexpectedEof);
        }

        Ok(buf.get_u32())
    }
}

// TODO needs u128? only cookie@kexinit

impl Pack for u128 {
    fn pack<P: Put>(&self, buf: &mut P) {
        buf.put(&self.to_be_bytes());
    }
}

impl Unpack for u128 {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        if buf.remaining() < 16 {
            return Err(UnpackError::UnexpectedEof);
        }

        Ok(buf.get_u128())
    }
}

impl Pack for str {
    fn pack<P: Put>(&self, buf: &mut P) {
        let bytes = self.as_bytes();
        (bytes.len() as u32).pack(buf);
        buf.put(bytes);
    }
}

impl Pack for String {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.as_str().pack(buf);
    }
}

impl Unpack for String {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let len = u32::unpack(buf)? as usize;
        if buf.remaining() < len {
            return Err(UnpackError::UnexpectedEof);
        }

        let s = buf.take(len).to_bytes();
        let s = String::from_utf8(s.to_vec())?;
        Ok(s)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mpint(Bytes);

impl Mpint {
    pub(crate) fn new<B: Into<Bytes>>(b: B) -> Self {
        Self(b.into())
    }
}

impl Pack for Mpint {
    fn pack<P: Put>(&self, buf: &mut P) {
        let (head, len) = if !self.0.is_empty() && self.0[0] & 0x80 != 0 {
            (&b"\x00"[..], self.0.len() + 1)
        } else {
            (&b""[..], self.0.len())
        };
        (len as u32).pack(buf);

        buf.put(head);
        buf.put(&self.0);
    }
}

impl Unpack for Mpint {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        Ok(Self(Bytes::unpack(buf)?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NameList(Vec<String>);

impl NameList {
    pub(crate) fn iter(&self) -> std::slice::Iter<String> {
        self.0.iter()
    }
}

impl<A> FromIterator<A> for NameList
where
    A: Into<String>,
{
    fn from_iter<T: IntoIterator<Item = A>>(iter: T) -> Self {
        let vec = iter.into_iter().map(Into::into).collect::<Vec<_>>();
        Self(vec)
    }
}

impl Pack for NameList {
    fn pack<P: Put>(&self, buf: &mut P) {
        let s = self.0.join(",");
        s.pack(buf);
    }
}

impl Unpack for NameList {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let s = String::unpack(buf)?;
        let s = s.split(',').map(Into::into).collect();
        Ok(Self(s))
    }
}

impl Pack for Bytes {
    fn pack<P: Put>(&self, buf: &mut P) {
        (self.len() as u32).pack(buf);
        buf.put(&self);
    }
}

impl Unpack for Bytes {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let len = u32::unpack(buf)? as usize;
        if buf.remaining() < len {
            return Err(UnpackError::UnexpectedEof);
        }

        let b = buf.take(len).to_bytes();
        Ok(b)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bool() {
        let mut b = BytesMut::new();
        true.pack(&mut b);
        assert_eq!(&*b, &[1][..]);

        let r = bool::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, true);
    }

    #[test]
    fn test_u8() {
        let mut b = BytesMut::new();
        12u8.pack(&mut b);
        assert_eq!(&*b, &[12][..]);

        let r = u8::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, 12);

        let mut b = Bytes::from("");
        let r = u8::unpack(&mut b);
        assert_eq!(r, Err(UnpackError::UnexpectedEof));
    }

    #[test]
    fn test_u32() {
        let mut b = BytesMut::new();
        12u32.pack(&mut b);
        assert_eq!(&*b, &[0, 0, 0, 12][..]);

        let r = u32::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, 12);

        let mut b = Bytes::from("abc");
        let r = u32::unpack(&mut b);
        assert_eq!(r, Err(UnpackError::UnexpectedEof));
    }

    #[test]
    fn test_u128() {
        let mut b = BytesMut::new();
        0xcafebabeu128.pack(&mut b);
        assert_eq!(
            &*b,
            &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xca, 0xfe, 0xba, 0xbe][..]
        );

        let r = u128::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, 0xcafebabe);

        let mut b = Bytes::from("abc");
        let r = u128::unpack(&mut b);
        assert_eq!(r, Err(UnpackError::UnexpectedEof));
    }

    #[test]
    fn test_str() {
        let mut b = BytesMut::new();
        "HELLO".pack(&mut b);
        assert_eq!(&*b, &[0, 0, 0, 5, b'H', b'E', b'L', b'L', b'O'][..]);

        let r = String::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, "HELLO");
    }

    #[test]
    fn test_string() {
        let mut b = BytesMut::new();
        "HELLO".to_string().pack(&mut b);
        assert_eq!(&*b, &[0, 0, 0, 5, b'H', b'E', b'L', b'L', b'O'][..]);

        let r = String::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, "HELLO");

        let mut b = Bytes::from(vec![0, 0, 0, 1]);
        let r = String::unpack(&mut b);
        assert_eq!(r, Err(UnpackError::UnexpectedEof));

        let mut b = Bytes::from(vec![0, 0, 0]);
        let r = String::unpack(&mut b);
        assert_eq!(r, Err(UnpackError::UnexpectedEof));
    }

    #[test]
    fn test_mpint() {
        let mut b = BytesMut::new();
        Mpint::new(vec![1]).pack(&mut b);
        assert_eq!(&*b, &[0, 0, 0, 1, 1][..]);

        let r = Mpint::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, Mpint::new(vec![1]));

        let mut b = BytesMut::new();
        Mpint::new(vec![]).pack(&mut b);
        assert_eq!(&*b, &[0, 0, 0, 0][..]);

        let r = Mpint::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, Mpint::new(vec![]));

        let mut b = BytesMut::new();
        Mpint::new(vec![0xFF]).pack(&mut b);
        assert_eq!(&*b, &[0, 0, 0, 2, 0x00, 0xFF][..]);

        let r = Mpint::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, Mpint::new(vec![0x00, 0xFF]));

        let mut b = Bytes::from(vec![0, 0, 0]);
        let r = Mpint::unpack(&mut b);
        assert_eq!(r, Err(UnpackError::UnexpectedEof));

        let mut b = Bytes::from(vec![0, 0, 0, 1]);
        let r = Mpint::unpack(&mut b);
        assert_eq!(r, Err(UnpackError::UnexpectedEof));
    }

    #[test]
    fn test_namelist() {
        let mut b = BytesMut::new();
        vec!["a"].into_iter().collect::<NameList>().pack(&mut b);
        assert_eq!(&*b, &[0, 0, 0, 1, b'a'][..]);

        let r = NameList::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, NameList(vec!["a".into()]));

        let mut b = BytesMut::new();
        vec!["a", "b"]
            .into_iter()
            .collect::<NameList>()
            .pack(&mut b);
        assert_eq!(&*b, &[0, 0, 0, 3, b'a', b',', b'b'][..]);

        let r = NameList::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, NameList(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn test_bytes() {
        let mut b = BytesMut::new();
        Bytes::from("abc").pack(&mut b);
        assert_eq!(&*b, &[0, 0, 0, 3, b'a', b'b', b'c'][..]);

        let r = Bytes::unpack(&mut b.freeze()).unwrap();
        assert_eq!(r, Bytes::from("abc"));

        let mut b = Bytes::from(vec![0, 0, 0]);
        let r = Bytes::unpack(&mut b);
        assert_eq!(r, Err(UnpackError::UnexpectedEof));

        let mut b = Bytes::from(vec![0, 0, 0, 1]);
        let r = Bytes::unpack(&mut b);
        assert_eq!(r, Err(UnpackError::UnexpectedEof));
    }
}

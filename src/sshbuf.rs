use bytes::{Buf, BufMut};
use std::string::FromUtf8Error;

#[derive(Debug)]
pub enum SshBufError {
    Underflow,
    Overflow,
    FromUtf8Error(FromUtf8Error),
}

impl From<FromUtf8Error> for SshBufError {
    fn from(v: FromUtf8Error) -> Self {
        Self::FromUtf8Error(v)
    }
}

pub type SshBufResult<T> = Result<T, SshBufError>;

pub trait SshBuf: Buf {
    fn get_boolean(&mut self) -> SshBufResult<bool> {
        if !self.has_remaining() {
            return Err(SshBufError::Underflow);
        }

        let v = self.get_u8();
        Ok(match v {
            0 => false,
            _ => true,
        })
    }

    fn get_uint32(&mut self) -> SshBufResult<u32> {
        if self.remaining() < 4 {
            return Err(SshBufError::Underflow);
        }

        Ok(self.get_u32_be())
    }

    fn get_uint64(&mut self) -> SshBufResult<u64> {
        if self.remaining() < 8 {
            return Err(SshBufError::Underflow);
        }

        Ok(self.get_u64_be())
    }

    fn get_string(&mut self) -> SshBufResult<String> {
        let len = self.get_uint32()? as usize;

        if self.remaining() < len {
            return Err(SshBufError::Underflow);
        }

        let mut buf = vec![0; len];
        self.copy_to_slice(&mut buf);
        match String::from_utf8(buf) {
            Ok(e) => Ok(e),
            Err(e) => Err(e.into()),
        }
    }

    fn get_mpint(&mut self) -> SshBufResult<Vec<u8>> {
        let len = self.get_uint32()? as usize;

        if self.remaining() < len {
            return Err(SshBufError::Underflow);
        }

        let mut buf = vec![0; len];
        self.copy_to_slice(&mut buf);
        Ok(buf)
    }

    fn get_name_list(&mut self) -> SshBufResult<Vec<String>> {
        Ok(match &self.get_string()? {
            val if val.is_empty() => vec![],
            val => val.split(',').map(String::from).collect(),
        })
    }

    fn get_binary_string(&mut self) -> SshBufResult<Vec<u8>> {
        let len = self.get_uint32()? as usize;

        if self.remaining() < len {
            return Err(SshBufError::Underflow);
        }

        let mut buf = vec![0; len];
        self.copy_to_slice(&mut buf);
        Ok(buf)
    }
}

pub trait SshBufMut: BufMut {
    fn put_boolean(&mut self, v: bool) -> SshBufResult<()> {
        if !self.has_remaining_mut() {
            return Err(SshBufError::Overflow);
        };

        let v = if v { 1 } else { 0 };
        self.put_u8(v);
        Ok(())
    }

    fn put_uint32(&mut self, v: u32) -> SshBufResult<()> {
        if self.remaining_mut() < 4 {
            return Err(SshBufError::Overflow);
        }

        self.put_u32_be(v);
        Ok(())
    }

    fn put_uint64(&mut self, v: u64) -> SshBufResult<()> {
        if self.remaining_mut() < 8 {
            return Err(SshBufError::Overflow);
        }

        self.put_u64_be(v);
        Ok(())
    }

    fn put_string(&mut self, v: &str) -> SshBufResult<()> {
        let v = v.as_bytes();
        self.put_uint32(v.len() as u32)?;

        if self.remaining_mut() < v.len() {
            return Err(SshBufError::Overflow);
        }
        self.put_slice(v);
        Ok(())
    }

    fn put_mpint(&mut self, v: &[u8]) -> SshBufResult<()> {
        let (head, len) = if !v.is_empty() && v[0] & 0x80 != 0 {
            (&b"\x00"[..], v.len() + 1)
        } else {
            (&b""[..], v.len())
        };
        //self.put_uint32(v.len() as u32)?;
        self.put_uint32(len as u32)?;

        if self.remaining_mut() < len {
            return Err(SshBufError::Overflow);
        }
        self.put_slice(head);
        self.put_slice(v);
        Ok(())
    }

    fn put_name_list(&mut self, v: &[String]) -> SshBufResult<()> {
        self.put_string(&v.join(","))
    }

    fn put_binary_string(&mut self, v: &[u8]) -> SshBufResult<()> {
        self.put_uint32(v.len() as u32)?;

        if self.remaining_mut() < v.len() {
            return Err(SshBufError::Overflow);
        }
        self.put_slice(v);
        Ok(())
    }
}

impl<B: Buf> SshBuf for B {}
impl<B: BufMut> SshBufMut for B {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::io;

    #[test]
    fn test_boolean() {
        let mut buf = BytesMut::default();
        buf.put_boolean(true).unwrap();
        buf.put_boolean(false).unwrap();
        assert_eq!(buf, BytesMut::from(&[1, 0][..]));

        let mut buf = io::Cursor::new(buf);
        assert_eq!(buf.get_boolean().unwrap(), true);
        assert_eq!(buf.get_boolean().unwrap(), false);
    }

    #[test]
    fn test_uint32() {
        let mut buf = BytesMut::default();
        buf.put_uint32(0xcafebabe).unwrap();
        assert_eq!(buf, BytesMut::from(&[0xca, 0xfe, 0xba, 0xbe][..]));

        let mut buf = io::Cursor::new(buf);
        assert_eq!(buf.get_uint32().unwrap(), 0xcafebabe);
    }

    #[test]
    fn test_uint64() {
        let mut buf = BytesMut::default();
        buf.put_uint64(0xcafebabe).unwrap();
        assert_eq!(
            buf,
            BytesMut::from(&[0x00, 0x00, 0x00, 0x00, 0xca, 0xfe, 0xba, 0xbe][..])
        );

        let mut buf = io::Cursor::new(buf);
        assert_eq!(buf.get_uint64().unwrap(), 0xcafebabe);
    }

    #[test]
    fn test_string() {
        let mut buf = BytesMut::default();
        buf.put_string("").unwrap();
        buf.put_string("testing").unwrap();
        assert_eq!(
            buf,
            BytesMut::from(
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b't', b'e', b's', b't', b'i',
                    b'n', b'g'
                ][..]
            )
        );

        let mut buf = io::Cursor::new(buf);
        assert_eq!(buf.get_string().unwrap(), "");
        assert_eq!(buf.get_string().unwrap(), "testing");
    }

    #[test]
    fn test_mpint() {
        let mut buf = BytesMut::default();
        buf.put_mpint(&[][..]).unwrap();
        buf.put_mpint(&[0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7][..])
            .unwrap();
        assert_eq!(
            buf,
            BytesMut::from(
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x09, 0xa3, 0x78, 0xf9, 0xb2,
                    0xe3, 0x32, 0xa7
                ][..]
            )
        );

        let mut buf = io::Cursor::new(buf);
        assert_eq!(buf.get_mpint().unwrap(), vec![]);
        assert_eq!(
            buf.get_mpint().unwrap(),
            vec![0x09, 0xa3, 0x78, 0xf9, 0xb2, 0xe3, 0x32, 0xa7]
        );
    }

    #[test]
    fn test_name_list() {
        let mut buf = BytesMut::default();
        buf.put_name_list(&[][..]).unwrap();
        buf.put_name_list(&["zlib".into()][..]).unwrap();
        buf.put_name_list(&["zlib".into(), "none".into()][..])
            .unwrap();
        assert_eq!(
            buf,
            BytesMut::from(
                &[
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x7a, 0x6c, 0x69, 0x62, 0x00,
                    0x00, 0x00, 0x09, 0x7a, 0x6c, 0x69, 0x62, 0x2c, 0x6e, 0x6f, 0x6e, 0x65
                ][..]
            )
        );

        let mut buf = io::Cursor::new(buf);
        assert_eq!(buf.get_name_list().unwrap(), vec![] as Vec<String>);
        assert_eq!(
            buf.get_name_list().unwrap(),
            vec!["zlib".into()] as Vec<String>
        );
        assert_eq!(
            buf.get_name_list().unwrap(),
            vec!["zlib".into(), "none".into()] as Vec<String>
        );
    }
}

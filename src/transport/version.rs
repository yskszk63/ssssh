use std::io;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::codec::{Encoder, Decoder, FramedParts};
use bytes::{BytesMut, BufMut as _, Bytes};
use futures::{TryStreamExt as _, SinkExt as _};

#[derive(Debug)]
pub enum VersionExchangeError {
    InvalidFormat,
    Io(io::Error),
}

impl From<io::Error> for VersionExchangeError {
    fn from(v: io::Error) -> Self {
        Self::Io(v)
    }
}

pub type VersionExchangeResult<T> = Result<T, VersionExchangeError>;

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const CRLF: &[u8] = &[CR, LF];

#[derive(Debug)]
pub struct VersionCodec;

impl Encoder for VersionCodec {
    type Item = Bytes;
    type Error = VersionExchangeError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> VersionExchangeResult<()> {
        dst.put_slice(&item);
        dst.put_slice(CRLF);
        Ok(())
    }
}

impl Decoder for VersionCodec {
    type Item = Bytes;
    type Error = VersionExchangeError;

    fn decode(&mut self, src: &mut BytesMut) -> VersionExchangeResult<Option<Bytes>> {
        let cr_index = match src.iter().position(|b| *b == CR) {
            Some(e) => e,
            None => return Ok(None),
        };
        if src.get(cr_index +1) != Some(&LF) {
            return Err(Self::Error::InvalidFormat)
        }
        let result = src.split_to(cr_index).freeze();
        src.advance(2);
        Ok(Some(result))
    }
}

pub async fn exchange_version<IO>(connection: &mut IO, server_version: Bytes)
-> VersionExchangeResult<(Bytes, BytesMut)> where IO: AsyncRead + AsyncWrite + Unpin {
    let mut codec = VersionCodec.framed(connection);

    let client_version = loop {
        if let Some(e) = codec.try_next().await? {
            break e
        }
    };
    codec.send(server_version).await?;

    let FramedParts { read_buf, .. } = codec.into_parts();
    Ok((client_version, read_buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test() {
        let mut mock = Builder::new().read(b"SSH-2.0-cli\r\n").write(b"SSH-2.0-srv\r\n").build();

        let (srv, rb) = exchange_version(&mut mock, Bytes::from("SSH-2.0-srv")).await.unwrap();
        assert_eq!(srv, Bytes::from("SSH-2.0-cli"));
        assert_eq!(rb, Bytes::from(""));
    }

    #[tokio::test]
    async fn test2() {
        let mut mock = Builder::new().read(b"SSH-2.0-cli\r\nabcdefg").write(b"SSH-2.0-srv\r\n").build();

        let (srv, rb) = exchange_version(&mut mock, Bytes::from("SSH-2.0-srv")).await.unwrap();
        assert_eq!(srv, Bytes::from("SSH-2.0-cli"));
        assert_eq!(rb, Bytes::from("abcdefg"));
    }
}

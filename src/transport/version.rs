use std::io;

use bytes::{BufMut as _, Bytes, BytesMut};
use futures::{SinkExt as _, TryStreamExt as _};
use tokio::codec::{Decoder, Encoder, FramedParts};
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Debug)]
pub struct Version {
    client: Bytes,
    server: Bytes,
}

impl Version {
    pub async fn exchange<IO>(
        connection: &mut IO,
        server_version: impl Into<Bytes>,
    ) -> VersionExchangeResult<(Self, BytesMut)>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let mut codec = VersionCodec.framed(connection);

        let client_version = if let Some(e) = codec.try_next().await? {
            match &e.get(..8) {
                Some(b"SSH-2.0-") => e,
                _ => return Err(VersionExchangeError::InvalidFormat), // TODO
            }
        } else {
            return Err(VersionExchangeError::InvalidFormat);
        };

        let server_version = server_version.into();
        codec.send(server_version.clone()).await?;

        let FramedParts { read_buf, .. } = codec.into_parts();
        let result = Self {
            server: server_version,
            client: client_version,
        };
        Ok((result, read_buf))
    }

    pub fn client(&self) -> &Bytes {
        &self.client
    }

    pub fn server(&self) -> &Bytes {
        &self.server
    }
}

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
struct VersionCodec;

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
        if src.get(cr_index + 1) != Some(&LF) {
            return Err(Self::Error::InvalidFormat);
        }
        let result = src.split_to(cr_index).freeze();
        src.advance(2);
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test::io::Builder;

    #[tokio::test]
    async fn test() {
        let mut mock = Builder::new()
            .read(b"SSH-2.0-cli\r\n")
            .write(b"SSH-2.0-srv\r\n")
            .build();

        let (version, rb) = Version::exchange(&mut mock, Bytes::from("SSH-2.0-srv"))
            .await
            .unwrap();
        assert_eq!(version.client(), &Bytes::from("SSH-2.0-cli"));
        assert_eq!(version.server(), &Bytes::from("SSH-2.0-srv"));
        assert_eq!(rb, Bytes::new());
    }

    #[tokio::test]
    async fn test2() {
        let mut mock = Builder::new()
            .read(b"SSH-2.0-cli\r\nabcdefg")
            .write(b"SSH-2.0-srv\r\n")
            .build();

        let (version, rb) = Version::exchange(&mut mock, Bytes::from("SSH-2.0-srv"))
            .await
            .unwrap();
        assert_eq!(version.client(), &Bytes::from("SSH-2.0-cli"));
        assert_eq!(version.server(), &Bytes::from("SSH-2.0-srv"));
        assert_eq!(rb, Bytes::from("abcdefg"));
    }
}

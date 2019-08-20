use std::cmp;
use std::io::{self, BufRead as _};

use bytes::{Bytes, BytesMut};
use failure::Fail;
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
                _ => return Err(VersionExchangeError::InvalidFormat),
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

#[derive(Debug, Fail)]
#[allow(clippy::module_name_repetitions)]
pub enum VersionExchangeError {
    #[fail(display = "Invalid SSH identification string")]
    InvalidFormat,
    #[fail(display = "IO Error")]
    Io(#[fail(cause)] io::Error),
}

impl From<io::Error> for VersionExchangeError {
    fn from(v: io::Error) -> Self {
        Self::Io(v)
    }
}

#[allow(clippy::module_name_repetitions)]
pub type VersionExchangeResult<T> = Result<T, VersionExchangeError>;

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const CRLF: &[u8] = &[CR, LF];
const MAX_LENGTH: usize = 255;

#[derive(Debug)]
struct VersionCodec;

impl Encoder for VersionCodec {
    type Item = Bytes;
    type Error = VersionExchangeError;

    fn encode(&mut self, item: Self::Item, dst: &mut BytesMut) -> VersionExchangeResult<()> {
        dst.extend_from_slice(&item);
        dst.extend_from_slice(CRLF);
        Ok(())
    }
}

impl Decoder for VersionCodec {
    type Item = Bytes;
    type Error = VersionExchangeError;

    fn decode(&mut self, src: &mut BytesMut) -> VersionExchangeResult<Option<Bytes>> {
        let len = cmp::min(src.len(), MAX_LENGTH);

        let mut line = String::new();
        let n = (&src.as_ref()[..len]).read_line(&mut line)?;
        src.advance(n);

        if line.ends_with('\n') {
            line.pop();
            if line.ends_with('\r') {
                line.pop();
            }
        }

        Ok(Some(line.into()))
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

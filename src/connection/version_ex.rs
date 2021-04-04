use tokio::io::{split, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::SshError;

const MAX_BUFFER: usize = 255;

async fn vex_recv<IO>(mut io: IO) -> Result<String, SshError>
where
    IO: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(MAX_BUFFER);
    loop {
        let b = io.read_u8().await?;
        buf.push(b);
        if b == b'\n' {
            break;
        }
    }

    let result = match &buf[..] {
        [result @ .., b'\r', b'\n'] => result,
        [result @ .., b'\n'] => result, // for old libssh
        x => {
            return Err(SshError::InvalidVersion(
                String::from_utf8_lossy(x).to_string(),
            ))
        }
    };
    let result = String::from_utf8_lossy(&result);
    if !result.starts_with("SSH-2.0-") {
        return Err(SshError::InvalidVersion(result.to_string()));
    }
    Ok(result.to_string())
}

async fn vex_send<IO>(mut io: IO, name: &str) -> Result<String, SshError>
where
    IO: AsyncWrite + Unpin,
{
    let name = format!("SSH-2.0-{}", name);
    io.write_all(format!("{}\r\n", name).as_bytes()).await?;
    Ok(name)
}

pub(crate) async fn vex<IO>(io: IO, name: &str) -> Result<(String, String), SshError>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    let (rx, tx) = split(io);
    let (recv, send) = tokio::try_join!(vex_recv(rx), vex_send(tx, name))?;
    Ok((recv, send))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio_test::io::Builder;
    use tokio_test::*;

    #[tokio::test]
    async fn test_vex() {
        let mock = Builder::new()
            .read(b"SSH-2.0-ssh\r\n")
            .write(b"SSH-2.0-ssssh\r\n")
            .build();
        let (r, x) = super::vex(mock, "ssssh").await.unwrap();
        assert_eq!(&r, "SSH-2.0-ssh");
        assert_eq!(&x, "SSH-2.0-ssssh");
    }

    #[tokio::test]
    async fn test_vex_rest() {
        let mut mock = Builder::new()
            .read(b"SSH-2.0-ssh\r\na")
            .write(b"SSH-2.0-ssssh\r\n")
            .build();
        let (r, x) = super::vex(&mut mock, "ssssh").await.unwrap();
        assert_eq!(&r, "SSH-2.0-ssh");
        assert_eq!(&x, "SSH-2.0-ssssh");

        let mut rest = String::new();
        mock.read_to_string(&mut rest).await.unwrap();
        assert_eq!("a", rest);
    }

    #[tokio::test]
    async fn test_vex_empty() {
        let mock = Builder::new().read(b"").write(b"SSH-2.0-ssssh\r\n").build();
        let result = super::vex(mock, "ssssh").await;
        assert_err!(result);
    }

    #[tokio::test]
    async fn test_vex_too_long() {
        let mock = Builder::new()
            .read(&[0; 256])
            .write(b"SSH-2.0-ssssh\r\n")
            .build();
        let result = super::vex(mock, "ssssh").await;
        assert_err!(result);
    }

    #[tokio::test]
    async fn test_vex_ioerr() {
        let mock = Builder::new()
            .read_error(io::Error::new(io::ErrorKind::Other, ""))
            .build();
        let result = super::vex(mock, "ssssh").await;
        assert_err!(result);
    }

    #[tokio::test]
    async fn test_vex_lf() {
        let mock = Builder::new()
            .read(b"SSH-2.0-ssh\n")
            .write(b"SSH-2.0-ssssh\r\n")
            .build();
        let (r, x) = super::vex(mock, "ssssh").await.unwrap();
        assert_eq!(&r, "SSH-2.0-ssh");
        assert_eq!(&x, "SSH-2.0-ssssh");
    }

    #[tokio::test]
    async fn test_vex_invalid_version() {
        let mock = Builder::new().read(b"S\r\n").build();
        let result = super::vex(mock, "ssssh").await;
        assert_err!(result);
    }

    #[tokio::test]
    async fn test_vex_ioerr2() {
        let mock = Builder::new()
            .write_error(io::Error::new(io::ErrorKind::Other, ""))
            .build();
        let result = super::vex(mock, "ssssh").await;
        assert_err!(result);
    }
}

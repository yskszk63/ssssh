use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, Bytes, BytesMut};
use futures::ready;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::SshError;

#[derive(Debug)]
struct RecvState {
    buf: BytesMut,
    result: Option<String>,
}

#[derive(Debug)]
struct SendState {
    name: String,
    buf: Bytes,
    flushed: bool,
}

#[derive(Debug)]
pub(crate) struct VersionExchange<IO> {
    io: Option<IO>,
    recv: RecvState,
    send: SendState,
}

impl<IO> VersionExchange<IO> {
    pub(crate) fn new(io: IO, name: String) -> Self {
        let name = format!("SSH-2.0-{}", name);
        Self {
            io: Some(io),
            recv: RecvState {
                buf: BytesMut::new(),
                result: None,
            },
            send: SendState {
                buf: Bytes::from(format!("{}\r\n", name)),
                name,
                flushed: false,
            },
        }
    }
}

fn poll_recv<IO>(
    mut io: &mut IO,

    state: &mut RecvState,
    cx: &mut Context<'_>,
) -> Poll<Result<String, SshError>>
where
    IO: AsyncRead + Unpin,
{
    if let Some(result) = &state.result {
        return Poll::Ready(Ok(result.clone()));
    }

    let mut b = [0];
    loop {
        match ready!(Pin::new(&mut io).poll_read(cx, &mut b))? {
            0 => return Poll::Ready(Err(SshError::VersionUnexpectedEof(state.buf.clone()))),
            1 => {
                state.buf.extend_from_slice(&b);
                if state.buf.len() > 255 {
                    return Poll::Ready(Err(SshError::VersionTooLong));
                }
                if b[0] == b'\n' {
                    break;
                }
            }
            _ => unreachable!(),
        }
    }

    let result = match &state.buf[..] {
        [result @ .., b'\r', b'\n'] => result,
        [result @ .., b'\n'] => result, // for old libssh
        x => {
            return Poll::Ready(Err(SshError::InvalidVersion(
                String::from_utf8_lossy(x).to_string(),
            )))
        }
    };
    let result = String::from_utf8_lossy(&result);
    if !result.starts_with("SSH-2.0-") {
        return Poll::Ready(Err(SshError::InvalidVersion(result.to_string())));
    }
    let result = result.to_string();
    state.result = Some(result.clone());
    Poll::Ready(Ok(result))
}

fn poll_send<IO>(
    mut io: &mut IO,
    state: &mut SendState,
    cx: &mut Context<'_>,
) -> Poll<Result<String, SshError>>
where
    IO: AsyncWrite + Unpin,
{
    if !state.buf.has_remaining() && state.flushed {
        return Poll::Ready(Ok(state.name.clone()));
    }

    if state.buf.has_remaining() {
        ready!(Pin::new(&mut io).poll_write_buf(cx, &mut state.buf))?;
    }
    if !state.flushed {
        ready!(Pin::new(&mut io).poll_flush(cx))?;
    }
    Poll::Ready(Ok(state.name.clone()))
}

impl<IO> Future for VersionExchange<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = Result<(String, String, IO), SshError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        assert!(this.io.is_some());

        let recv = poll_recv(&mut this.io.as_mut().unwrap(), &mut this.recv, cx)?;
        let send = poll_send(&mut this.io.as_mut().unwrap(), &mut this.send, cx)?;
        match (recv, send) {
            (Poll::Ready(recv), Poll::Ready(send)) => {
                Poll::Ready(Ok((recv, send, this.io.take().unwrap())))
            }
            _ => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use tokio_test::io::Builder;
    use tokio_test::*;

    #[tokio::test]
    async fn test_vex() {
        fn assert<P: Send + Unpin + 'static>() {}
        assert::<VersionExchange<tokio::net::TcpStream>>();

        let mock = Builder::new()
            .read(b"SSH-2.0-ssh\r\n")
            .write(b"SSH-2.0-ssssh\r\n")
            .build();
        let vex = VersionExchange::new(mock, "ssssh".into());
        let (r, x, _) = vex.await.unwrap();
        assert_eq!(&r, "SSH-2.0-ssh");
        assert_eq!(&x, "SSH-2.0-ssssh");
    }

    #[tokio::test]
    async fn test_vex_empty() {
        let mock = Builder::new().read(b"").write(b"SSH-2.0-ssssh\r\n").build();
        let vex = VersionExchange::new(mock, "ssssh".into());
        assert_err!(vex.await);
    }

    #[tokio::test]
    async fn test_vex_too_long() {
        let mock = Builder::new()
            .read(&[0; 256])
            .write(b"SSH-2.0-ssssh\r\n")
            .build();
        let vex = VersionExchange::new(mock, "ssssh".into());
        assert_err!(vex.await);
    }

    #[tokio::test]
    async fn test_vex_ioerr() {
        let mock = Builder::new()
            .read_error(io::Error::new(io::ErrorKind::Other, ""))
            .write(b"SSH-2.0-ssssh\r\n")
            .build();
        let vex = VersionExchange::new(mock, "ssssh".into());
        assert_err!(vex.await);
    }

    #[tokio::test]
    async fn test_vex_lf() {
        let mock = Builder::new()
            .read(b"SSH-2.0-ssh\n")
            .write(b"SSH-2.0-ssssh\r\n")
            .build();
        let vex = VersionExchange::new(mock, "ssssh".into());
        let (r, x, _) = vex.await.unwrap();
        assert_eq!(&r, "SSH-2.0-ssh");
        assert_eq!(&x, "SSH-2.0-ssssh");
    }

    #[tokio::test]
    async fn test_vex_invalid_version() {
        let mock = Builder::new()
            .read(b"S\r\n")
            .write(b"SSH-2.0-ssssh\r\n")
            .build();
        let vex = VersionExchange::new(mock, "ssssh".into());
        assert_err!(vex.await);
    }

    #[tokio::test]
    async fn test_vex_ioerr2() {
        let mock = Builder::new()
            .write_error(io::Error::new(io::ErrorKind::Other, ""))
            .build();
        let vex = VersionExchange::new(mock, "ssssh".into());
        assert_err!(vex.await);
    }
}

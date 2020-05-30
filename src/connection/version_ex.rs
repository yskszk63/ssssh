use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, Bytes, BytesMut};
use futures::ready;
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, BufStream};

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
    io: Option<BufStream<IO>>,
    recv: RecvState,
    send: SendState,
}

impl<IO> VersionExchange<IO> {
    pub(crate) fn new(io: BufStream<IO>, name: String) -> Self {
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
    IO: AsyncBufRead + Unpin,
{
    if let Some(result) = &state.result {
        return Poll::Ready(Ok(result.clone()));
    }

    let buf = ready!(Pin::new(&mut io).poll_fill_buf(cx))?;
    if buf.is_empty() {
        return Poll::Ready(Err(SshError::VersionUnexpectedEof(state.buf.clone())));
    }

    match buf.iter().position(|b| *b == b'\n') {
        Some(p) => {
            let p = p + 1;
            if p + state.buf.len() > 255 {
                return Poll::Ready(Err(SshError::VersionTooLong));
            }
            state.buf.extend_from_slice(&buf[..p]);
            Pin::new(&mut io).consume(p);
        }
        None => {
            let n = buf.len();
            if n + state.buf.len() > 255 {
                return Poll::Ready(Err(SshError::VersionTooLong));
            }
            Pin::new(&mut io).consume(n);
            return Poll::Pending;
        }
    };

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
    type Output = Result<(String, String, BufStream<IO>), SshError>;

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

    #[test]
    fn test() {
        fn assert<P: Send + Unpin + 'static>() {}
        assert::<VersionExchange<tokio::net::TcpStream>>();
    }
}

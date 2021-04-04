use std::os::unix::io::{AsRawFd, IntoRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};
use tokio_pipe::{PipeRead, PipeWrite};

/// SSH data input.
#[derive(Debug)]
pub struct SshInput(PipeRead);

impl SshInput {
    pub(crate) fn new(inner: PipeRead) -> Self {
        Self(inner)
    }
}

impl AsyncRead for SshInput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsRawFd for SshInput {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for SshInput {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

/// SSH data output.
#[derive(Debug)]
pub struct SshOutput(PipeWrite);

impl SshOutput {
    pub(crate) fn new(inner: PipeWrite) -> Self {
        Self(inner)
    }
}

impl AsyncWrite for SshOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl AsRawFd for SshOutput {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}

impl IntoRawFd for SshOutput {
    fn into_raw_fd(self) -> RawFd {
        self.0.into_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ssh_input() {
        use tokio::io::AsyncWriteExt;
        use tokio_pipe::pipe;

        let (rx, mut tx) = pipe().unwrap();
        let mut rx = SshInput::new(rx);

        tokio::spawn(async move {
            tx.write_all(b"Hello, World!").await.unwrap();
        });

        let mut b = vec![];
        let n = tokio::io::copy(&mut rx, &mut b).await.unwrap();
        assert_eq!(b"Hello, World!".len(), n as usize);
    }
}

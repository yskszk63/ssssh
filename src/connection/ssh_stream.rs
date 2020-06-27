use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::buf::{Buf, BufMut};
use tokio::io::{self, AsyncRead, AsyncWrite};
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
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }

    fn poll_read_buf<B: BufMut>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<io::Result<usize>>
    where
        Self: Sized,
    {
        Pin::new(&mut self.0).poll_read_buf(cx, buf)
    }

    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        self.0.prepare_uninitialized_buffer(buf)
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

    fn poll_write_buf<B: Buf>(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut B,
    ) -> Poll<Result<usize, io::Error>>
    where
        Self: Sized,
    {
        Pin::new(&mut self.0).poll_write_buf(cx, buf)
    }
}

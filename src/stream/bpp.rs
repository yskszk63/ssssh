//! Binary Packet Protocol
//!
//! [Binary Packet Protocol](https://tools.ietf.org/html/rfc4253#section-4.2)
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use futures::ready;
use futures::sink::Sink;
use futures::stream::Stream;
use ring::rand::{SecureRandom, SystemRandom};
use thiserror::Error;
use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite, BufStream};

use crate::comp::CompressionError;
use crate::encrypt::EncryptError;
use crate::mac::MacError;
use crate::state::State;

pub(crate) const MAXIMUM_PACKET_SIZE: usize = 35000;

#[derive(Debug, Error)]
pub enum DecodeError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    EncryptError(#[from] EncryptError),

    #[error(transparent)]
    CompressionError(#[from] CompressionError),

    #[error(transparent)]
    MacError(#[from] MacError),

    #[error("too large packet length {0}")]
    TooLargePacket(usize),
}

#[derive(Debug, Error)]
pub enum EncodeError {
    #[error(transparent)]
    Io(#[from] io::Error),

    #[error(transparent)]
    EncryptError(#[from] EncryptError),

    #[error(transparent)]
    CompressionError(#[from] CompressionError),

    #[error(transparent)]
    MacError(#[from] MacError),

    #[error("failed to fill pad")]
    PadFillError,
}

fn pad_len(len: usize, bs: usize) -> usize {
    const MINIMUM_PAD_SIZE: usize = 4;

    let pad = (1 + len + MINIMUM_PAD_SIZE) % bs;
    if pad > (bs - MINIMUM_PAD_SIZE) {
        bs * 2 - pad
    } else {
        bs - pad
    }
}

#[derive(Debug)]
enum DecryptState {
    FillFirst,
    FillRemaining { len: usize },
}

#[derive(Debug)]
pub(crate) struct BppStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    state: State,
    io: BufStream<IO>,
    txbuf: (BytesMut, BytesMut), // enc, plain
    rxbuf: (BytesMut, BytesMut), // enc, plain
    rxstate: DecryptState,
}

impl<IO> BppStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(io: BufStream<IO>) -> Self {
        let state = State::new();
        let rxstate = DecryptState::FillFirst;
        Self {
            state,
            io,
            txbuf: (BytesMut::new(), BytesMut::new()),
            rxbuf: (BytesMut::new(), BytesMut::new()),
            rxstate,
        }
    }

    pub(crate) fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

impl<IO> Stream for BppStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Item = Result<Bytes, DecodeError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let bs = this.state.ctos().encrypt().block_size();
        let mac_length = this.state.ctos().mac().len();

        match Pin::new(&mut this.io).poll_fill_buf(cx) {
            Poll::Ready(buf) => {
                let buf = buf?;
                let n = buf.len();
                this.rxbuf.0.put(buf);
                Pin::new(&mut this.io).consume(n);
                if n == 0 {
                    return Poll::Ready(None);
                }
            }
            Poll::Pending => {
                if this.rxbuf.0.has_remaining() {
                } else {
                    return Poll::Pending;
                }
            }
        };

        loop {
            match &mut this.rxstate {
                DecryptState::FillFirst => {
                    if this.rxbuf.0.remaining() < bs {
                        return Poll::Pending;
                    }

                    this.state
                        .ctos_mut()
                        .encrypt_mut()
                        .update(&this.rxbuf.0[..bs], &mut this.rxbuf.1)?;

                    let len = (&this.rxbuf.1[..4]).get_u32() as usize;
                    if len + 4 + mac_length > MAXIMUM_PACKET_SIZE {
                        return Poll::Ready(Some(Err(DecodeError::TooLargePacket(len + 4 + mac_length))))
                    }
                    this.rxstate = DecryptState::FillRemaining { len };
                }
                DecryptState::FillRemaining { len } => {
                    if this.rxbuf.0.remaining() < *len + 4 + mac_length {
                        return Poll::Pending;
                    }
                    let buf = this.rxbuf.0.split_to(*len + 4 + mac_length);

                    this.state
                        .ctos_mut()
                        .encrypt_mut()
                        .update(&buf[bs..(*len + 4)], &mut this.rxbuf.1)?;

                    let plain = this.rxbuf.1.split();

                    let expect = &buf[(*len + 4)..];
                    let seq = this.state.ctos_mut().get_and_inc_seq();
                    this.state.ctos().mac().verify(
                        seq,
                        &plain[..(*len + 4)],
                        &buf[..(*len + 4)],
                        &expect,
                    )?;

                    let pad = plain[4] as usize;
                    let mut payload = &plain[5..(*len + 4 - pad)];
                    let payload = this
                        .state
                        .ctos_mut()
                        .comp()
                        .decompress(&payload.to_bytes())?;

                    this.rxstate = DecryptState::FillFirst;

                    return Poll::Ready(Some(Ok(payload)));
                }
            }
        }
    }
}

impl<IO> Sink<Bytes> for BppStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Error = EncodeError;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        if !this.txbuf.0.is_empty() {
            ready!(Pin::new(this).poll_flush(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: Bytes) -> Result<(), Self::Error> {
        let this = self.get_mut();

        let item = this.state.stoc().comp().compress(&item)?;
        let len = item.len();
        let bs = this.state.stoc().encrypt().block_size();
        let padding_length = pad_len(len, bs);
        let len = len + padding_length + 1;

        let mut pad = vec![0; padding_length];
        SystemRandom::new()
            .fill(&mut pad)
            .map_err(|_| EncodeError::PadFillError)?;

        this.txbuf.1.put_u32(len as u32);
        this.txbuf.1.put_u8(pad.len() as u8);
        this.txbuf.1.put_slice(&item);
        this.txbuf.1.put_slice(&pad);

        this.state
            .stoc_mut()
            .encrypt_mut()
            .update(&this.txbuf.1, &mut this.txbuf.0)?;

        let seq = this.state.stoc_mut().get_and_inc_seq();
        let sign = this
            .state
            .stoc()
            .mac()
            .sign(seq, &this.txbuf.1, &this.txbuf.0)?;
        this.txbuf.0.put_slice(&sign);
        this.txbuf.1.clear();

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.io).poll_write(cx, &this.txbuf.0))?;
        this.txbuf.0.clear();
        ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        ready!(Pin::new(&mut this.io).poll_shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<BppStream<tokio::net::TcpStream>>();
        assert::<DecodeError>();
        assert::<EncodeError>();
    }
}

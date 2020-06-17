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
use tokio::io::{AsyncRead, AsyncWrite};

use crate::state::State;
use crate::SshError;

pub(crate) const MAXIMUM_PACKET_SIZE: usize = 35000;

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
    io: IO,
    txbuf: BytesMut,
    rxbuf: BytesMut,
    rxstate: DecryptState,
}

impl<IO> BppStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    pub(crate) fn new(io: IO) -> Self {
        let state = State::new();
        let rxstate = DecryptState::FillFirst;
        Self {
            state,
            io,
            txbuf: BytesMut::new(),
            rxbuf: BytesMut::new(),
            rxstate,
        }
    }

    pub(crate) fn state(&self) -> &State {
        &self.state
    }

    pub(crate) fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

impl<IO> Stream for BppStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Item = Result<Bytes, SshError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        let bs = this.state.ctos().encrypt().block_size();
        let mac_length = this.state.ctos().mac().len();

        this.rxbuf.reserve(MAXIMUM_PACKET_SIZE);
        match Pin::new(&mut this.io).poll_read_buf(cx, &mut this.rxbuf) {
            Poll::Ready(Ok(0)) => return Poll::Ready(None),
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e.into()))),
            Poll::Pending if this.rxbuf.has_remaining() => {}
            Poll::Pending => return Poll::Pending,
        }

        loop {
            match &mut this.rxstate {
                DecryptState::FillFirst => {
                    if this.rxbuf.remaining() < bs {
                        return Poll::Pending;
                    }

                    this.state
                        .ctos_mut()
                        .encrypt_mut()
                        .update(&mut this.rxbuf[..bs])?;

                    let len = (&this.rxbuf[..4]).get_u32() as usize;
                    if len + 4 + mac_length > MAXIMUM_PACKET_SIZE {
                        return Poll::Ready(Some(Err(SshError::TooLargePacket(
                            len + 4 + mac_length,
                        ))));
                    }
                    this.rxstate = DecryptState::FillRemaining { len };
                }
                DecryptState::FillRemaining { len } => {
                    if this.rxbuf.remaining() < *len + 4 + mac_length {
                        return Poll::Pending;
                    }
                    let mut buf = this.rxbuf.split_to(*len + 4 + mac_length);

                    this.state
                        .ctos_mut()
                        .encrypt_mut()
                        .update(&mut buf[bs..(*len + 4)])?;

                    let expect = &buf[(*len + 4)..];
                    let seq = this.state.ctos_mut().get_and_inc_seq();
                    this.state
                        .ctos()
                        .mac()
                        .verify(seq, &buf[..(*len + 4)], &expect)?;

                    let pad = buf[4] as usize;
                    let mut payload = &buf[5..(*len + 4 - pad)];
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

impl<IO> Sink<&[u8]> for BppStream<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Error = SshError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.txbuf.remaining() > MAXIMUM_PACKET_SIZE {
            self.as_mut().poll_flush(cx)
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn start_send(self: Pin<&mut Self>, item: &[u8]) -> Result<(), Self::Error> {
        let this = self.get_mut();

        let item = this.state.stoc().comp().compress(item)?;
        let len = item.len();
        let bs = this.state.stoc().encrypt().block_size();
        let padding_length = pad_len(len, bs);
        let len = len + padding_length + 1;

        let mut pad = vec![0; padding_length];
        SystemRandom::new().fill(&mut pad).map_err(SshError::any)?;

        let mut buf = this.txbuf.split();

        buf.put_u32(len as u32);
        buf.put_u8(pad.len() as u8);
        buf.put_slice(&item);
        buf.put_slice(&pad);

        let seq = this.state.stoc_mut().get_and_inc_seq();
        let sign = this.state.stoc().mac().sign(seq, &buf)?;

        this.state.stoc_mut().encrypt_mut().update(&mut buf)?;

        buf.put_slice(&sign);

        this.txbuf.unsplit(buf);

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        while this.txbuf.has_remaining() {
            ready!(Pin::new(&mut this.io).poll_write_buf(cx, &mut this.txbuf))?;
        }
        this.txbuf.clear();
        ready!(Pin::new(&mut this.io).poll_flush(cx))?;
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let mut this = self.get_mut();
        ready!(Pin::new(&mut this).poll_flush(cx))?;
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
    }
}

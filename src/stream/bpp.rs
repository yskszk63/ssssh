//! Binary Packet Protocol
//!
//! [Binary Packet Protocol](https://tools.ietf.org/html/rfc4253#section-6)
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};
use futures::ready;
use futures::sink::Sink;
use futures::stream::Stream;
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::state::{OneWayState, State};
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
    FillRemaining(usize),
}

#[derive(Debug)]
pub(crate) struct BppStream<IO> {
    state: State,
    io: IO,
    rxstate: DecryptState,
    rxbuf: BytesMut,
    txbuf: BytesMut,
}

impl<IO> BppStream<IO> {
    pub(crate) fn new(io: IO) -> Self {
        Self {
            state: State::new(),
            io,
            rxstate: DecryptState::FillFirst,
            rxbuf: BytesMut::with_capacity(MAXIMUM_PACKET_SIZE),
            txbuf: BytesMut::with_capacity(MAXIMUM_PACKET_SIZE),
        }
    }

    pub(crate) fn state(&self) -> &State {
        &self.state
    }

    pub(crate) fn state_mut(&mut self) -> &mut State {
        &mut self.state
    }
}

fn poll_fill_buf<IO>(
    io: Pin<&mut IO>,
    cx: &mut Context<'_>,
    buf: &mut BytesMut,
) -> Poll<Result<usize, SshError>>
where
    IO: AsyncRead + Unpin,
{
    let n = {
        let dst = buf.chunk_mut();
        let dst = unsafe { &mut *(dst as *mut _ as *mut [MaybeUninit<u8>]) };
        let mut buf = ReadBuf::uninit(dst);
        let ptr = buf.filled().as_ptr();
        ready!(io.poll_read(cx, &mut buf)?);

        assert_eq!(ptr, buf.filled().as_ptr());
        buf.filled().len()
    };

    unsafe { buf.advance_mut(n) }
    Poll::Ready(Ok(n))
}

fn consume(buf: &mut BytesMut, amt: usize) {
    buf.advance(amt);
    if buf.is_empty() {
        buf.clear();
    }
}

fn next_payload(
    buf: &mut BytesMut,
    state: &mut OneWayState,
    txstate: &mut DecryptState,
) -> Poll<Result<Bytes, SshError>> {
    let mac_length = state.mac().len();

    loop {
        match txstate {
            DecryptState::FillFirst => {
                if buf.remaining() < 4 {
                    return Poll::Pending;
                }

                state.cipher_mut().update(&mut buf[..4])?;
                let len = (&buf[..4]).get_u32() as usize;
                if len + 4 + mac_length > MAXIMUM_PACKET_SIZE {
                    return Poll::Ready(Err(SshError::TooLargePacket(len + 4 + mac_length)));
                }
                *txstate = DecryptState::FillRemaining(len);
            }
            DecryptState::FillRemaining(len) => {
                if buf.remaining() < 4 + *len + mac_length {
                    return Poll::Pending;
                }

                let pkt_and_mac = &mut buf[..(4 + *len + mac_length)];
                state.cipher_mut().update(&mut pkt_and_mac[4..(4 + *len)])?;
                let pkt = &pkt_and_mac[..(4 + *len)];
                let mac = &pkt_and_mac[(*len + 4)..];
                let seq = state.get_and_inc_seq();
                state.mac().verify(seq, &pkt[..(*len + 4)], &mac)?;

                let pad = pkt[4] as usize;
                let payload = &pkt[(1 + 4)..(*len + 4 - pad)];
                let payload = state.comp().decompress(payload)?;

                consume(buf, 4 + *len + mac_length);
                *txstate = DecryptState::FillFirst;
                return Poll::Ready(Ok(payload));
            }
        }
    }
}

impl<IO> Stream for BppStream<IO>
where
    IO: AsyncRead + Unpin,
{
    type Item = Result<Bytes, SshError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let Self {
            ref mut io,
            ref mut state,
            ref mut rxstate,
            ref mut rxbuf,
            ..
        } = self.get_mut();
        let state = state.ctos_mut();

        loop {
            if let Poll::Ready(payload) = next_payload(rxbuf, state, rxstate)? {
                return Poll::Ready(Some(Ok(payload)));
            }
            let n = ready!(poll_fill_buf(Pin::new(io), cx, rxbuf))?;
            if n == 0 && rxbuf.is_empty() {
                return Poll::Ready(None);
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
        let Self {
            ref mut txbuf,
            ref mut state,
            ..
        } = self.get_mut();
        let state = state.stoc_mut();

        let item = state.comp().compress(item)?;
        let len = item.len();
        let bs = state.cipher().block_size();
        let padding_length = pad_len(len, bs);
        let len = len + padding_length + 1;

        let mut pad = vec![0; padding_length];
        SystemRandom::new().fill(&mut pad).map_err(SshError::any)?;

        let mut buf = txbuf.split();

        buf.put_u32(len as u32);
        buf.put_u8(pad.len() as u8);
        buf.put_slice(&item);
        buf.put_slice(&pad);

        let seq = state.get_and_inc_seq();
        let sign = state.mac().sign(seq, &buf)?;

        state.cipher_mut().update(&mut buf)?;

        buf.put_slice(&sign);

        txbuf.unsplit(buf);

        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        while this.txbuf.has_remaining() {
            let n = ready!(Pin::new(&mut this.io).poll_write(cx, &this.txbuf))?;
            this.txbuf.advance(n);
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
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        fn assert<T: Send + Sync + 'static>() {}

        assert::<BppStream<tokio::net::TcpStream>>();
    }
}

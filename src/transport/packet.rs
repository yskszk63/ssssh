use bytes::Bytes;

#[derive(Debug)]
pub(crate) struct Packet {
    seq: u32,
    data: Bytes,
}

impl Packet {
    pub(crate) fn new(seq: u32, data: Bytes) -> Self {
        Self { seq, data }
    }

    pub(crate) fn seq(&self) -> u32 {
        self.seq
    }

    pub(crate) fn data(&self) -> Bytes {
        self.data.clone()
    }
}

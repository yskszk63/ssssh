use super::*;

#[derive(Debug)]
pub(crate) struct Unknown {
    data: Bytes,
}

impl Unknown {
    pub(super) fn new(data: Bytes) -> Self {
        Self { data }
    }
}

impl Pack for Unknown {
    fn pack<P: Put>(&self, buf: &mut P) {
        buf.put(&self.data);
    }
}

impl Unpack for Unknown {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let data = buf.copy_to_bytes(buf.remaining());
        Ok(Self { data })
    }
}

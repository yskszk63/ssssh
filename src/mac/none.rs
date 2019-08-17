use bytes::Bytes;

use super::{Mac, MacResult};

#[allow(clippy::module_name_repetitions)]
pub struct NoneMac;

impl Mac for NoneMac {
    fn size(&self) -> usize {
        0
    }
    fn name(&self) -> &'static str {
        "none"
    }
    fn sign(&self, _seq: u32, _plain: &Bytes, _encrypted: &Bytes) -> MacResult<Bytes> {
        Ok(Bytes::from(""))
    }
}

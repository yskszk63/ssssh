use bytes::Bytes;

use super::MacType;

#[allow(clippy::module_name_repetitions)]
pub(crate) struct NoneMac;

impl MacType for NoneMac {
    fn size(&self) -> usize {
        0
    }
    fn name(&self) -> &'static str {
        "none"
    }
    fn sign(&self, _seq: u32, _plain: &Bytes, _encrypted: &Bytes) -> Bytes {
        Bytes::new()
    }
}

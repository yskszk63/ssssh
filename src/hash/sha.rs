use ring::digest::{Context, SHA1_FOR_LEGACY_USE_ONLY as SHA1, SHA256, SHA512};
use std::fmt;

use super::*;

pub(crate) struct Sha1(Context);

impl Put for Sha1 {
    fn put(&mut self, src: &[u8]) {
        self.0.update(src)
    }
}

impl HasherTrait for Sha1 {
    fn new() -> Self {
        Self(Context::new(&SHA1))
    }

    fn finish(self) -> Bytes {
        let hash = self.0.finish();
        let mut hash = hash.as_ref();
        hash.copy_to_bytes(hash.remaining())
    }
}

impl fmt::Debug for Sha1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha1")
    }
}

pub(crate) struct Sha256(Context);

impl Put for Sha256 {
    fn put(&mut self, src: &[u8]) {
        self.0.update(src)
    }
}

impl HasherTrait for Sha256 {
    fn new() -> Self {
        Self(Context::new(&SHA256))
    }

    fn finish(self) -> Bytes {
        let hash = self.0.finish();
        let mut hash = hash.as_ref();
        hash.copy_to_bytes(hash.remaining())
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256")
    }
}

pub(crate) struct Sha512(Context);

impl Put for Sha512 {
    fn put(&mut self, src: &[u8]) {
        self.0.update(src)
    }
}

impl HasherTrait for Sha512 {
    fn new() -> Self {
        Self(Context::new(&SHA512))
    }

    fn finish(self) -> Bytes {
        let hash = self.0.finish();
        let mut hash = hash.as_ref();
        hash.copy_to_bytes(hash.remaining())
    }
}

impl fmt::Debug for Sha512 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha512")
    }
}

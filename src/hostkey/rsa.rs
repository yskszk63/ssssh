use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private};
use openssl::rsa::{Padding, Rsa as OpenSslRsa};
use openssl::sign::Signer;

use super::*;
use crate::pack::Mpint;

#[derive(Debug)]
pub(crate) struct Rsa {
    pair: OpenSslRsa<Private>,
}

impl HostKeyTrait for Rsa {
    const NAME: &'static str = "ssh-rsa";

    fn gen() -> Result<Self, GenError> {
        let pair = OpenSslRsa::generate(2048)
            .map_err(|e| Box::new(e) as Box<dyn StdError + Send + Sync>)?;
        Ok(Self { pair })
    }

    fn publickey(&self) -> Bytes {
        let mut b = BytesMut::new();
        Mpint::new(self.pair.e().to_vec()).pack(&mut b);
        Mpint::new(self.pair.n().to_vec()).pack(&mut b);
        b.freeze()
    }

    fn sign(&self, target: &Bytes) -> Bytes {
        let pkey = PKey::from_rsa(self.pair.clone()).unwrap();
        let mut signer = Signer::new(MessageDigest::sha1(), &pkey).unwrap();
        signer.set_rsa_padding(Padding::PKCS1).unwrap();
        signer.update(target.as_ref()).unwrap();
        signer.sign_to_vec().unwrap().into()
    }
}

impl From<Rsa> for HostKey {
    fn from(v: Rsa) -> Self {
        Self::Rsa(v)
    }
}

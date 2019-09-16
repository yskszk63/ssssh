use std::io::Cursor;

use bytes::{Bytes, BytesMut};

use super::{Message, MessageResult};
use crate::hostkey::{HostKey, Signature};
use crate::sshbuf::SshBufMut as _;

#[derive(Debug)]
pub(crate) struct KexEcdhReply {
    public_host_key: HostKey,
    ephemeral_public_key: Vec<u8>,
    signature: Signature,
}

impl KexEcdhReply {
    pub(crate) fn new(
        public_host_key: HostKey,
        ephemeral_public_key: &[u8],
        signature: Signature,
    ) -> Self {
        let ephemeral_public_key = Vec::from(ephemeral_public_key);
        Self {
            public_host_key,
            ephemeral_public_key,
            signature,
        }
    }

    pub(crate) fn from(_buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        /*
        let public_host_key = buf.get_binary_string()?;
        let ephemeral_public_key = buf.get_binary_string()?;
        let signature = buf.get_binary_string()?;
        Ok(Self {
            public_host_key,
            ephemeral_public_key,
            signature,
        })
        */
        unimplemented!()
    }

    pub(crate) fn put(&self, buf: &mut BytesMut) {
        self.public_host_key.put_to(buf);
        buf.put_binary_string(&self.ephemeral_public_key);
        self.signature.put_to(buf);
    }
}

impl From<KexEcdhReply> for Message {
    fn from(v: KexEcdhReply) -> Self {
        Self::KexEcdhReply(v)
    }
}

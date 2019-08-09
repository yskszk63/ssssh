use std::io::Cursor;

use bytes::{Buf as _, BufMut as _, Bytes, BytesMut};

use super::{Message, MessageId, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Default)]
pub struct Builder {
    kex_algorithms: Vec<String>,
    server_host_key_algorithms: Vec<String>,
    encryption_algorithms_client_to_server: Vec<String>,
    encryption_algorithms_server_to_client: Vec<String>,
    mac_algorithms_client_to_server: Vec<String>,
    mac_algorithms_server_to_client: Vec<String>,
    compression_algorithms_client_to_server: Vec<String>,
    compression_algorithms_server_to_client: Vec<String>,
    languages_client_to_server: Vec<String>,
    languages_server_to_client: Vec<String>,
    first_kex_packet_follows: bool,
}

impl Builder {
    pub fn kex_algorithms(&mut self, val: impl IntoIterator<Item = String>) -> &mut Self {
        self.kex_algorithms.extend(val);
        self
    }
    pub fn server_host_key_algorithms(
        &mut self,
        val: impl IntoIterator<Item = String>,
    ) -> &mut Self {
        self.server_host_key_algorithms.extend(val);
        self
    }
    pub fn encryption_algorithms_client_to_server(
        &mut self,
        val: impl IntoIterator<Item = String>,
    ) -> &mut Self {
        self.encryption_algorithms_client_to_server.extend(val);
        self
    }
    pub fn encryption_algorithms_server_to_client(
        &mut self,
        val: impl IntoIterator<Item = String>,
    ) -> &mut Self {
        self.encryption_algorithms_server_to_client.extend(val);
        self
    }
    pub fn mac_algorithms_client_to_server(
        &mut self,
        val: impl IntoIterator<Item = String>,
    ) -> &mut Self {
        self.mac_algorithms_client_to_server.extend(val);
        self
    }
    pub fn mac_algorithms_server_to_client(
        &mut self,
        val: impl IntoIterator<Item = String>,
    ) -> &mut Self {
        self.mac_algorithms_server_to_client.extend(val);
        self
    }
    pub fn compression_algorithms_client_to_server(
        &mut self,
        val: impl IntoIterator<Item = String>,
    ) -> &mut Self {
        self.compression_algorithms_client_to_server.extend(val);
        self
    }
    pub fn compression_algorithms_server_to_client(
        &mut self,
        val: impl IntoIterator<Item = String>,
    ) -> &mut Self {
        self.compression_algorithms_server_to_client.extend(val);
        self
    }
    pub fn languages_client_to_server(
        &mut self,
        val: impl IntoIterator<Item = String>,
    ) -> &mut Self {
        self.languages_client_to_server.extend(val);
        self
    }
    pub fn languages_server_to_client(
        &mut self,
        val: impl IntoIterator<Item = String>,
    ) -> &mut Self {
        self.languages_server_to_client.extend(val);
        self
    }
    pub fn first_kex_packet_follows(&mut self, val: bool) -> &mut Self {
        self.first_kex_packet_follows = val;
        self
    }
    pub fn build(&mut self, cookie: [u8; 16]) -> Kexinit {
        Kexinit {
            cookie,
            kex_algorithms: self.kex_algorithms.clone(),
            server_host_key_algorithms: self.server_host_key_algorithms.clone(),
            encryption_algorithms_client_to_server: self
                .encryption_algorithms_client_to_server
                .clone(),
            encryption_algorithms_server_to_client: self
                .encryption_algorithms_server_to_client
                .clone(),
            mac_algorithms_client_to_server: self.mac_algorithms_client_to_server.clone(),
            mac_algorithms_server_to_client: self.mac_algorithms_server_to_client.clone(),
            compression_algorithms_client_to_server: self
                .compression_algorithms_client_to_server
                .clone(),
            compression_algorithms_server_to_client: self
                .compression_algorithms_server_to_client
                .clone(),
            languages_client_to_server: self.languages_client_to_server.clone(),
            languages_server_to_client: self.languages_server_to_client.clone(),
            first_kex_packet_follows: self.first_kex_packet_follows,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Kexinit {
    cookie: [u8; 16],
    kex_algorithms: Vec<String>,
    server_host_key_algorithms: Vec<String>,
    encryption_algorithms_client_to_server: Vec<String>,
    encryption_algorithms_server_to_client: Vec<String>,
    mac_algorithms_client_to_server: Vec<String>,
    mac_algorithms_server_to_client: Vec<String>,
    compression_algorithms_client_to_server: Vec<String>,
    compression_algorithms_server_to_client: Vec<String>,
    languages_client_to_server: Vec<String>,
    languages_server_to_client: Vec<String>,
    first_kex_packet_follows: bool,
}

impl Kexinit {
    pub fn cookie(&self) -> [u8; 16] {
        self.cookie.clone()
    }

    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn from(mut buf: Cursor<Bytes>) -> MessageResult<Kexinit> {
        let mut cookie = [0; 16];
        buf.copy_to_slice(&mut cookie);

        let v = Kexinit::builder()
            .kex_algorithms(buf.get_name_list()?)
            .server_host_key_algorithms(buf.get_name_list()?)
            .encryption_algorithms_client_to_server(buf.get_name_list()?)
            .encryption_algorithms_server_to_client(buf.get_name_list()?)
            .mac_algorithms_client_to_server(buf.get_name_list()?)
            .mac_algorithms_server_to_client(buf.get_name_list()?)
            .compression_algorithms_client_to_server(buf.get_name_list()?)
            .compression_algorithms_server_to_client(buf.get_name_list()?)
            .languages_client_to_server(buf.get_name_list()?)
            .languages_server_to_client(buf.get_name_list()?)
            .first_kex_packet_follows(buf.get_boolean()?)
            .build(cookie);
        buf.get_uint32()?;
        Ok(v)
    }

    pub fn put(&self, buf: &mut BytesMut) -> MessageResult<()> {
        buf.put_u8(MessageId::Kexinit as u8);
        buf.put_slice(&self.cookie);
        buf.put_name_list(&self.kex_algorithms)?;
        buf.put_name_list(&self.server_host_key_algorithms)?;
        buf.put_name_list(&self.encryption_algorithms_client_to_server)?;
        buf.put_name_list(&self.encryption_algorithms_server_to_client)?;
        buf.put_name_list(&self.mac_algorithms_client_to_server)?;
        buf.put_name_list(&self.mac_algorithms_server_to_client)?;
        buf.put_name_list(&self.compression_algorithms_client_to_server)?;
        buf.put_name_list(&self.compression_algorithms_server_to_client)?;
        buf.put_name_list(&self.languages_client_to_server)?;
        buf.put_name_list(&self.languages_server_to_client)?;
        buf.put_boolean(self.first_kex_packet_follows)?;
        buf.put_uint32(0)?;

        Ok(())
    }
}

impl From<Kexinit> for Message {
    fn from(v: Kexinit) -> Message {
        Message::Kexinit(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::IntoBuf as _;

    #[test]
    fn test() {
        let m = Kexinit::builder().build([0xff; 16]);

        let mut buf = BytesMut::with_capacity(1024 * 8);
        m.put(&mut buf).unwrap();
        buf.advance(1);
        Kexinit::from(buf.freeze().into_buf()).unwrap();
    }
}

use std::io::Cursor;

use bytes::{Buf as _, Bytes, BytesMut};
use rand::{thread_rng, RngCore as _};

use super::{Message, MessageId, MessageResult};
use crate::sshbuf::{SshBuf as _, SshBufMut as _};

#[derive(Debug, Default)]
pub struct Builder {
    cookie: Option<[u8; 16]>,
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
    pub fn cookie(&mut self, val: [u8; 16]) -> &mut Self {
        self.cookie = Some(val);
        self
    }

    pub fn kex_algorithms(
        &mut self,
        val: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.kex_algorithms.extend(val.into_iter().map(Into::into));
        self
    }
    pub fn server_host_key_algorithms(
        &mut self,
        val: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.server_host_key_algorithms
            .extend(val.into_iter().map(Into::into));
        self
    }
    pub fn encryption_algorithms_client_to_server(
        &mut self,
        val: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.encryption_algorithms_client_to_server
            .extend(val.into_iter().map(Into::into));
        self
    }
    pub fn encryption_algorithms_server_to_client(
        &mut self,
        val: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.encryption_algorithms_server_to_client
            .extend(val.into_iter().map(Into::into));
        self
    }
    pub fn mac_algorithms_client_to_server(
        &mut self,
        val: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.mac_algorithms_client_to_server
            .extend(val.into_iter().map(Into::into));
        self
    }
    pub fn mac_algorithms_server_to_client(
        &mut self,
        val: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.mac_algorithms_server_to_client
            .extend(val.into_iter().map(Into::into));
        self
    }
    pub fn compression_algorithms_client_to_server(
        &mut self,
        val: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.compression_algorithms_client_to_server
            .extend(val.into_iter().map(Into::into));
        self
    }
    pub fn compression_algorithms_server_to_client(
        &mut self,
        val: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.compression_algorithms_server_to_client
            .extend(val.into_iter().map(Into::into));
        self
    }
    pub fn languages_client_to_server(
        &mut self,
        val: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.languages_client_to_server
            .extend(val.into_iter().map(Into::into));
        self
    }
    pub fn languages_server_to_client(
        &mut self,
        val: impl IntoIterator<Item = impl Into<String>>,
    ) -> &mut Self {
        self.languages_server_to_client
            .extend(val.into_iter().map(Into::into));
        self
    }
    pub fn first_kex_packet_follows(&mut self, val: bool) -> &mut Self {
        self.first_kex_packet_follows = val;
        self
    }
    pub fn build(&mut self) -> Kexinit {
        let cookie = self.cookie.unwrap_or_else(|| {
            let mut cookie = [0; 16];
            thread_rng().fill_bytes(&mut cookie);
            cookie
        });

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
    pub fn builder() -> Builder {
        Builder::default()
    }

    pub fn kex_algorithms(&self) -> impl Iterator<Item = &String> {
        self.kex_algorithms.iter()
    }

    pub fn server_host_key_algorithms(&self) -> impl Iterator<Item = &String> {
        self.server_host_key_algorithms.iter()
    }

    pub fn encryption_algorithms_client_to_server(&self) -> impl Iterator<Item = &String> {
        self.encryption_algorithms_client_to_server.iter()
    }

    pub fn encryption_algorithms_server_to_client(&self) -> impl Iterator<Item = &String> {
        self.encryption_algorithms_server_to_client.iter()
    }

    pub fn mac_algorithms_client_to_server(&self) -> impl Iterator<Item = &String> {
        self.mac_algorithms_client_to_server.iter()
    }

    pub fn mac_algorithms_server_to_client(&self) -> impl Iterator<Item = &String> {
        self.mac_algorithms_server_to_client.iter()
    }

    pub fn compression_algorithms_client_to_server(&self) -> impl Iterator<Item = &String> {
        self.compression_algorithms_client_to_server.iter()
    }

    pub fn compression_algorithms_server_to_client(&self) -> impl Iterator<Item = &String> {
        self.compression_algorithms_server_to_client.iter()
    }

    pub fn from(buf: &mut Cursor<Bytes>) -> MessageResult<Self> {
        let mut cookie = [0; 16];
        buf.copy_to_slice(&mut cookie);

        let v = Self::builder()
            .cookie(cookie)
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
            .build();
        buf.get_uint32()?;
        Ok(v)
    }

    pub fn put(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(&self.cookie); // u128?
        buf.put_name_list(&self.kex_algorithms);
        buf.put_name_list(&self.server_host_key_algorithms);
        buf.put_name_list(&self.encryption_algorithms_client_to_server);
        buf.put_name_list(&self.encryption_algorithms_server_to_client);
        buf.put_name_list(&self.mac_algorithms_client_to_server);
        buf.put_name_list(&self.mac_algorithms_server_to_client);
        buf.put_name_list(&self.compression_algorithms_client_to_server);
        buf.put_name_list(&self.compression_algorithms_server_to_client);
        buf.put_name_list(&self.languages_client_to_server);
        buf.put_name_list(&self.languages_server_to_client);
        buf.put_boolean(self.first_kex_packet_follows);
        buf.put_uint32(0);
    }

    pub fn to_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&vec![MessageId::Kexinit.into()]);
        self.put(&mut buf);
        buf.freeze()
    }
}

impl From<Kexinit> for Message {
    fn from(v: Kexinit) -> Self {
        Self::Kexinit(Box::new(v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::IntoBuf as _;

    #[test]
    fn test() {
        let m = Kexinit::builder().build();

        let mut buf = BytesMut::new();
        m.put(&mut buf);
        Kexinit::from(&mut buf.freeze().into_buf()).unwrap();
    }
}

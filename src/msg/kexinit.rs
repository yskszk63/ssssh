use derive_builder::Builder;
use getset::Getters;

use super::*;

pub(crate) type BoxKexinit = Box<Kexinit>;

impl MsgItem for BoxKexinit {
    const ID: u8 = Kexinit::ID;
}

impl Pack for BoxKexinit {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.as_ref().pack(buf)
    }
}

impl Unpack for BoxKexinit {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        Ok(Box::new(Kexinit::unpack(buf)?))
    }
}

impl From<BoxKexinit> for Msg {
    fn from(v: BoxKexinit) -> Self {
        Self::Kexinit(v)
    }
}

#[derive(Debug, Clone, Getters, Builder)]
pub(crate) struct Kexinit {
    #[get = "pub(crate)"]
    cookie: u128,
    #[get = "pub(crate)"]
    kex_algorithms: NameList,
    #[get = "pub(crate)"]
    server_host_key_algorithms: NameList,
    #[get = "pub(crate)"]
    encryption_algorithms_c2s: NameList,
    #[get = "pub(crate)"]
    encryption_algorithms_s2c: NameList,
    #[get = "pub(crate)"]
    mac_algorithms_c2s: NameList,
    #[get = "pub(crate)"]
    mac_algorithms_s2c: NameList,
    #[get = "pub(crate)"]
    compression_algorithms_c2s: NameList,
    #[get = "pub(crate)"]
    compression_algorithms_s2c: NameList,
    #[get = "pub(crate)"]
    languages_c2s: NameList,
    #[get = "pub(crate)"]
    languages_s2c: NameList,
    #[get = "pub(crate)"]
    first_kex_packet_follows: bool,
}

impl MsgItem for Kexinit {
    const ID: u8 = 20;
}

impl Pack for Kexinit {
    fn pack<P: Put>(&self, buf: &mut P) {
        self.cookie.pack(buf);
        self.kex_algorithms.pack(buf);
        self.server_host_key_algorithms.pack(buf);
        self.encryption_algorithms_c2s.pack(buf);
        self.encryption_algorithms_s2c.pack(buf);
        self.mac_algorithms_c2s.pack(buf);
        self.mac_algorithms_s2c.pack(buf);
        self.compression_algorithms_c2s.pack(buf);
        self.compression_algorithms_s2c.pack(buf);
        self.languages_c2s.pack(buf);
        self.languages_s2c.pack(buf);
        self.first_kex_packet_follows.pack(buf);
        0u32.pack(buf); // (reserved for future extension)
    }
}

impl Unpack for Kexinit {
    fn unpack<B: Buf>(buf: &mut B) -> Result<Self, UnpackError> {
        let cookie = Unpack::unpack(buf)?;
        let kex_algorithms = Unpack::unpack(buf)?;
        let server_host_key_algorithms = Unpack::unpack(buf)?;
        let encryption_algorithms_c2s = Unpack::unpack(buf)?;
        let encryption_algorithms_s2c = Unpack::unpack(buf)?;
        let mac_algorithms_c2s = Unpack::unpack(buf)?;
        let mac_algorithms_s2c = Unpack::unpack(buf)?;
        let compression_algorithms_c2s = Unpack::unpack(buf)?;
        let compression_algorithms_s2c = Unpack::unpack(buf)?;
        let languages_c2s = Unpack::unpack(buf)?;
        let languages_s2c = Unpack::unpack(buf)?;
        let first_kex_packet_follows = Unpack::unpack(buf)?;
        u32::unpack(buf)?; // (reserved for future extension)

        Ok(Self {
            cookie,
            kex_algorithms,
            server_host_key_algorithms,
            encryption_algorithms_c2s,
            encryption_algorithms_s2c,
            mac_algorithms_c2s,
            mac_algorithms_s2c,
            compression_algorithms_c2s,
            compression_algorithms_s2c,
            languages_c2s,
            languages_s2c,
            first_kex_packet_follows,
        })
    }
}

impl From<Kexinit> for Msg {
    fn from(v: Kexinit) -> Self {
        Self::Kexinit(Box::new(v))
    }
}

use std::time::Duration;

use getset::{Getters, MutGetters};

use crate::comp::Compression;
use crate::encrypt::Encrypt;
use crate::hostkey::HostKeys;
use crate::kex::Kex;
use crate::mac::Mac;
use crate::msg::kexinit::{Kexinit, KexinitBuilder};

#[derive(Debug, Getters, MutGetters)]
pub(crate) struct Preference {
    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    kex_algorithms: Vec<String>,

    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    hostkeys: HostKeys,

    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    encryption_algorithms: Vec<String>,

    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    mac_algorithms: Vec<String>,

    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    compression_algorithms: Vec<String>,

    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    name: String,

    #[get = "pub(crate)"]
    #[get_mut = "pub(crate)"]
    timeout: Option<Duration>,
}

impl Default for Preference {
    fn default() -> Self {
        Self {
            kex_algorithms: Kex::defaults(),
            hostkeys: HostKeys::new(),
            encryption_algorithms: Encrypt::defaults(),
            mac_algorithms: Mac::defaults(),
            compression_algorithms: Compression::defaults(),
            name: "sssh".into(),
            timeout: None,
        }
    }
}

impl Preference {
    pub(crate) fn to_kexinit(&self, cookie: u128) -> Kexinit {
        KexinitBuilder::default()
            .cookie(cookie)
            .kex_algorithms(self.kex_algorithms.clone().into_iter().collect())
            .server_host_key_algorithms(self.hostkeys.names().into_iter().collect())
            .encryption_algorithms_c2s(self.encryption_algorithms.clone().into_iter().collect())
            .encryption_algorithms_s2c(self.encryption_algorithms.clone().into_iter().collect())
            .mac_algorithms_c2s(self.mac_algorithms.clone().into_iter().collect())
            .mac_algorithms_s2c(self.mac_algorithms.clone().into_iter().collect())
            .compression_algorithms_c2s(self.compression_algorithms.clone().into_iter().collect())
            .compression_algorithms_s2c(self.compression_algorithms.clone().into_iter().collect())
            .languages_c2s(Vec::<String>::new().into_iter().collect())
            .languages_s2c(Vec::<String>::new().into_iter().collect())
            .first_kex_packet_follows(false)
            .build()
            .unwrap()
    }
}

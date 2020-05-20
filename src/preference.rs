use std::path::Path;
use std::time::Duration;

use getset::Getters;

use crate::comp::Compression;
use crate::encrypt::Encrypt;
use crate::hostkey::{GenError, HostKeys, HostKeysBuilder};
use crate::kex::Kex;
use crate::mac::Mac;
use crate::msg::kexinit::{Kexinit, KexinitBuilder};

#[derive(Debug, Default)]
pub(crate) struct PreferenceBuilder {
    kex_algorithms: Vec<String>,
    hostkeys: HostKeysBuilder,
    encryption_algorithms: Vec<String>,
    mac_algorithms: Vec<String>,
    compression_algorithms: Vec<String>,
    name: Option<String>,
    timeout: Option<Duration>,
}

impl PreferenceBuilder {
    pub(crate) fn add_kex_algorithm(&mut self, name: &str) -> &mut Self {
        self.kex_algorithms.push(name.to_string());
        self
    }

    pub(crate) fn add_encryption_algorithm(&mut self, name: &str) -> &mut Self {
        self.encryption_algorithms.push(name.to_string());
        self
    }

    pub(crate) fn add_mac_algorithm(&mut self, name: &str) -> &mut Self {
        self.mac_algorithms.push(name.to_string());
        self
    }

    pub(crate) fn add_compression_algorithm(&mut self, name: &str) -> &mut Self {
        self.compression_algorithms.push(name.to_string());
        self
    }

    pub(crate) fn name(&mut self, name: &str) -> &mut Self {
        self.name = Some(name.to_string());
        self
    }

    pub(crate) fn timeout(&mut self, timeout: Duration) -> &mut Self {
        self.timeout = Some(timeout);
        self
    }

    pub(crate) fn hostkeys_from_dir<P: AsRef<Path>>(&mut self, dir: P) -> &mut Self {
        self.hostkeys.load_from_dir(dir);
        self
    }

    pub(crate) fn hostkeys_from_path<P: AsRef<Path>>(&mut self, name: &str, file: P) -> &mut Self {
        self.hostkeys.load_from_file(name, file);
        self
    }

    pub(crate) fn hostkeys_generate(&mut self) -> &mut Self {
        self.hostkeys.generate();
        self
    }

    pub(crate) fn build(&self) -> Result<Preference, GenError> {
        let kex_algorithms = if self.kex_algorithms.is_empty() {
            Kex::defaults()
        } else {
            // TODO check names
            self.kex_algorithms.clone()
        };

        let encryption_algorithms = if self.encryption_algorithms.is_empty() {
            Encrypt::defaults()
        } else {
            // TODO check names
            self.encryption_algorithms.clone()
        };

        let mac_algorithms = if self.mac_algorithms.is_empty() {
            Mac::defaults()
        } else {
            // TODO check names
            self.mac_algorithms.clone()
        };

        let compression_algorithms = if self.compression_algorithms.is_empty() {
            Compression::defaults()
        } else {
            // TODO check names
            self.compression_algorithms.clone()
        };

        let name = self.name.clone().unwrap_or_else(|| "sssh".into());
        let timeout = self.timeout.clone();

        let mut hostkeys = self.hostkeys.build()?;
        if hostkeys.names().is_empty() {
            hostkeys.generate()?;
        }

        Ok(Preference {
            kex_algorithms,
            hostkeys,
            encryption_algorithms,
            mac_algorithms,
            compression_algorithms,
            name,
            timeout,
        })
    }
}

#[derive(Debug, Getters)]
pub(crate) struct Preference {
    #[get = "pub(crate)"]
    kex_algorithms: Vec<String>,

    #[get = "pub(crate)"]
    hostkeys: HostKeys,

    #[get = "pub(crate)"]
    encryption_algorithms: Vec<String>,

    #[get = "pub(crate)"]
    mac_algorithms: Vec<String>,

    #[get = "pub(crate)"]
    compression_algorithms: Vec<String>,

    #[get = "pub(crate)"]
    name: String,

    #[get = "pub(crate)"]
    timeout: Option<Duration>,
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

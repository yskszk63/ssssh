use std::path::Path;
use std::time::Duration;

use getset::Getters;

use crate::comp;
use crate::encrypt;
use crate::hostkey::{HostKeys, HostKeysBuilder};
use crate::kex;
use crate::mac;
use crate::msg::kexinit::{Kexinit, KexinitBuilder};
use crate::negotiate::AlgorithmName;
use crate::SshError;

#[derive(Debug, Default)]
pub(crate) struct PreferenceBuilder {
    kex_algorithms: Vec<kex::Algorithm>,
    hostkeys: HostKeysBuilder,
    encryption_algorithms: Vec<encrypt::Algorithm>,
    mac_algorithms: Vec<mac::Algorithm>,
    compression_algorithms: Vec<comp::Algorithm>,
    name: Option<String>,
    timeout: Option<Duration>,
}

impl PreferenceBuilder {
    pub(crate) fn add_kex_algorithm(&mut self, name: kex::Algorithm) -> &mut Self {
        self.kex_algorithms.push(name);
        self
    }

    pub(crate) fn add_encryption_algorithm(&mut self, name: encrypt::Algorithm) -> &mut Self {
        self.encryption_algorithms.push(name);
        self
    }

    pub(crate) fn add_mac_algorithm(&mut self, name: mac::Algorithm) -> &mut Self {
        self.mac_algorithms.push(name);
        self
    }

    pub(crate) fn add_compression_algorithm(&mut self, name: comp::Algorithm) -> &mut Self {
        self.compression_algorithms.push(name);
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

    pub(crate) fn hostkeys_from_path<P: AsRef<Path>>(&mut self, file: P) -> &mut Self {
        self.hostkeys.load_from_file(file);
        self
    }

    pub(crate) fn hostkeys_generate(&mut self) -> &mut Self {
        self.hostkeys.generate();
        self
    }

    pub(crate) async fn build(&self) -> Result<Preference, SshError> {
        let kex_algorithms = if self.kex_algorithms.is_empty() {
            kex::Algorithm::defaults()
        } else {
            self.kex_algorithms.clone()
        };

        let encryption_algorithms = if self.encryption_algorithms.is_empty() {
            encrypt::Algorithm::defaults()
        } else {
            self.encryption_algorithms.clone()
        };

        let mac_algorithms = if self.mac_algorithms.is_empty() {
            mac::Algorithm::defaults()
        } else {
            self.mac_algorithms.clone()
        };

        let compression_algorithms = if self.compression_algorithms.is_empty() {
            comp::Algorithm::defaults()
        } else {
            self.compression_algorithms.clone()
        };

        let name = self.name.clone().unwrap_or_else(|| "sssh".into());
        let timeout = self.timeout;

        let mut hostkeys = self.hostkeys.build().await?;
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
    kex_algorithms: Vec<kex::Algorithm>,

    #[get = "pub(crate)"]
    hostkeys: HostKeys,

    #[get = "pub(crate)"]
    encryption_algorithms: Vec<encrypt::Algorithm>,

    #[get = "pub(crate)"]
    mac_algorithms: Vec<mac::Algorithm>,

    #[get = "pub(crate)"]
    compression_algorithms: Vec<comp::Algorithm>,

    #[get = "pub(crate)"]
    name: String,

    #[get = "pub(crate)"]
    timeout: Option<Duration>,
}

fn generate_cookie() -> u128 {
    use ring::rand::{SecureRandom as _, SystemRandom};
    let mut cookie = 0u128.to_ne_bytes();
    SystemRandom::new().fill(&mut cookie).unwrap();
    u128::from_ne_bytes(cookie)
}

impl Preference {
    pub(crate) fn to_kexinit(&self) -> Kexinit {
        let cookie = generate_cookie();

        KexinitBuilder::default()
            .cookie(cookie)
            .kex_algorithms(
                self.kex_algorithms
                    .iter()
                    .map(AlgorithmName::to_string)
                    .collect(),
            )
            .server_host_key_algorithms(
                self.hostkeys
                    .names()
                    .iter()
                    .map(AlgorithmName::to_string)
                    .collect(),
            )
            .encryption_algorithms_c2s(
                self.encryption_algorithms
                    .iter()
                    .map(AlgorithmName::to_string)
                    .collect(),
            )
            .encryption_algorithms_s2c(
                self.encryption_algorithms
                    .iter()
                    .map(AlgorithmName::to_string)
                    .collect(),
            )
            .mac_algorithms_c2s(
                self.mac_algorithms
                    .iter()
                    .map(AlgorithmName::to_string)
                    .collect(),
            )
            .mac_algorithms_s2c(
                self.mac_algorithms
                    .iter()
                    .map(AlgorithmName::to_string)
                    .collect(),
            )
            .compression_algorithms_c2s(
                self.compression_algorithms
                    .iter()
                    .map(AlgorithmName::to_string)
                    .collect(),
            )
            .compression_algorithms_s2c(
                self.compression_algorithms
                    .iter()
                    .map(AlgorithmName::to_string)
                    .collect(),
            )
            .languages_c2s(Vec::<String>::new().into_iter().collect())
            .languages_s2c(Vec::<String>::new().into_iter().collect())
            .first_kex_packet_follows(false)
            .build()
            .unwrap()
    }
}

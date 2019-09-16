use failure::Fail;

use crate::msg::Kexinit;
use crate::named::Named;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub(crate) enum KexAlgorithm {
    Curve25519Sha256,
    DiffieHellmanGroup14Sha1,
}

impl Named for KexAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            Self::Curve25519Sha256 => "curve25519-sha256",
            Self::DiffieHellmanGroup14Sha1 => "diffie-hellman-group14-sha1",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub enum HostKeyAlgorithm {
    SshEd25519,
}

impl Named for HostKeyAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            Self::SshEd25519 => "ssh-ed25519",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub(crate) enum EncryptionAlgorithm {
    Aes256Ctr,
}

impl Named for EncryptionAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            Self::Aes256Ctr => "aes256-ctr",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub(crate) enum MacAlgorithm {
    HmacSha2_256,
}

impl Named for MacAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            Self::HmacSha2_256 => "hmac-sha2-256",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub(crate) enum CompressionAlgorithm {
    None,
}

impl Named for CompressionAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Preference {
    kex_algorithms: Vec<KexAlgorithm>,
    server_host_key_algorithms: Vec<HostKeyAlgorithm>,
    encryption_algorithms_client_to_server: Vec<EncryptionAlgorithm>,
    encryption_algorithms_server_to_client: Vec<EncryptionAlgorithm>,
    mac_algorithms_client_to_server: Vec<MacAlgorithm>,
    mac_algorithms_server_to_client: Vec<MacAlgorithm>,
    compression_algorithms_client_to_server: Vec<CompressionAlgorithm>,
    compression_algorithms_server_to_client: Vec<CompressionAlgorithm>,
}

impl Preference {
    pub(crate) fn to_kexinit(&self) -> Kexinit {
        Kexinit::builder()
            .kex_algorithms(self.kex_algorithms.iter().map(Named::name))
            .server_host_key_algorithms(self.server_host_key_algorithms.iter().map(Named::name))
            .encryption_algorithms_client_to_server(
                self.encryption_algorithms_client_to_server
                    .iter()
                    .map(Named::name),
            )
            .encryption_algorithms_server_to_client(
                self.encryption_algorithms_server_to_client
                    .iter()
                    .map(Named::name),
            )
            .mac_algorithms_client_to_server(
                self.mac_algorithms_client_to_server.iter().map(Named::name),
            )
            .mac_algorithms_server_to_client(
                self.mac_algorithms_server_to_client.iter().map(Named::name),
            )
            .compression_algorithms_client_to_server(
                self.compression_algorithms_client_to_server
                    .iter()
                    .map(Named::name),
            )
            .compression_algorithms_server_to_client(
                self.compression_algorithms_server_to_client
                    .iter()
                    .map(Named::name),
            )
            .build()
    }
}

impl Default for Preference {
    fn default() -> Self {
        Self {
            kex_algorithms: vec![
                KexAlgorithm::Curve25519Sha256,
                KexAlgorithm::DiffieHellmanGroup14Sha1,
            ],
            server_host_key_algorithms: vec![HostKeyAlgorithm::SshEd25519],
            encryption_algorithms_client_to_server: vec![EncryptionAlgorithm::Aes256Ctr],
            encryption_algorithms_server_to_client: vec![EncryptionAlgorithm::Aes256Ctr],
            mac_algorithms_client_to_server: vec![MacAlgorithm::HmacSha2_256],
            mac_algorithms_server_to_client: vec![MacAlgorithm::HmacSha2_256],
            compression_algorithms_client_to_server: vec![CompressionAlgorithm::None],
            compression_algorithms_server_to_client: vec![CompressionAlgorithm::None],
        }
    }
}

#[derive(Debug, Fail)]
pub enum NegotiateError {
    #[fail(display = "Negotiation mismatch kex: {:?} host: {:?} enc: {:?}{:?} mac: {:?}{:?} comp: {:?}{:?}",
    kex, server_host, encryption_c2s, encryption_s2c, mac_c2s, mac_s2c, compression_c2s, compression_s2c)]
    Missing {
        kex: Vec<String>,
        server_host: Vec<String>,
        encryption_c2s: Vec<String>,
        encryption_s2c: Vec<String>,
        mac_c2s: Vec<String>,
        mac_s2c: Vec<String>,
        compression_c2s: Vec<String>,
        compression_s2c: Vec<String>,
    },
}

#[derive(Debug)]
pub(crate) struct Algorithm {
    kex_algorithm: KexAlgorithm,
    server_host_key_algorithm: HostKeyAlgorithm,
    encryption_algorithm_client_to_server: EncryptionAlgorithm,
    encryption_algorithm_server_to_client: EncryptionAlgorithm,
    mac_algorithm_client_to_server: MacAlgorithm,
    mac_algorithm_server_to_client: MacAlgorithm,
    compression_algorithm_client_to_server: CompressionAlgorithm,
    compression_algorithm_server_to_client: CompressionAlgorithm,
}

impl Algorithm {
    pub(crate) fn negotiate(client: &Kexinit, server: &Preference) -> Result<Self, NegotiateError> {
        let kex_algorithm = client
            .kex_algorithms()
            .flat_map(|e| server.kex_algorithms.iter().filter(move |s| e == s.name()))
            .next();

        let server_host_key_algorithm = client
            .server_host_key_algorithms()
            .flat_map(|e| {
                server
                    .server_host_key_algorithms
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next();

        let encryption_algorithm_client_to_server = client
            .encryption_algorithms_client_to_server()
            .flat_map(|e| {
                server
                    .encryption_algorithms_client_to_server
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next();

        let encryption_algorithm_server_to_client = client
            .encryption_algorithms_server_to_client()
            .flat_map(|e| {
                server
                    .encryption_algorithms_server_to_client
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next();

        let mac_algorithm_client_to_server = client
            .mac_algorithms_client_to_server()
            .flat_map(|e| {
                server
                    .mac_algorithms_client_to_server
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next();

        let mac_algorithm_server_to_client = client
            .mac_algorithms_server_to_client()
            .flat_map(|e| {
                server
                    .mac_algorithms_server_to_client
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next();

        let compression_algorithm_client_to_server = client
            .compression_algorithms_client_to_server()
            .flat_map(|e| {
                server
                    .compression_algorithms_client_to_server
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next();

        let compression_algorithm_server_to_client = client
            .compression_algorithms_server_to_client()
            .flat_map(|e| {
                server
                    .compression_algorithms_server_to_client
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next();

        match (
            kex_algorithm,
            server_host_key_algorithm,
            encryption_algorithm_client_to_server,
            encryption_algorithm_server_to_client,
            mac_algorithm_client_to_server,
            mac_algorithm_server_to_client,
            compression_algorithm_client_to_server,
            compression_algorithm_server_to_client,
        ) {
            (
                Some(kex_algorithm),
                Some(server_host_key_algorithm),
                Some(encryption_algorithm_client_to_server),
                Some(encryption_algorithm_server_to_client),
                Some(mac_algorithm_client_to_server),
                Some(mac_algorithm_server_to_client),
                Some(compression_algorithm_client_to_server),
                Some(compression_algorithm_server_to_client),
            ) => Ok(Self {
                kex_algorithm: kex_algorithm.clone(),
                server_host_key_algorithm: server_host_key_algorithm.clone(),
                encryption_algorithm_server_to_client: encryption_algorithm_client_to_server
                    .clone(),
                encryption_algorithm_client_to_server: encryption_algorithm_server_to_client
                    .clone(),
                mac_algorithm_client_to_server: mac_algorithm_client_to_server.clone(),
                mac_algorithm_server_to_client: mac_algorithm_server_to_client.clone(),
                compression_algorithm_client_to_server: compression_algorithm_client_to_server
                    .clone(),
                compression_algorithm_server_to_client: compression_algorithm_server_to_client
                    .clone(),
            }),
            _ => Err(NegotiateError::Missing {
                kex: client.kex_algorithms().into_iter().cloned().collect(),
                server_host: client
                    .server_host_key_algorithms()
                    .into_iter()
                    .cloned()
                    .collect(),
                encryption_c2s: client
                    .encryption_algorithms_client_to_server()
                    .into_iter()
                    .cloned()
                    .collect(),
                encryption_s2c: client
                    .encryption_algorithms_server_to_client()
                    .into_iter()
                    .cloned()
                    .collect(),
                mac_c2s: client
                    .mac_algorithms_client_to_server()
                    .into_iter()
                    .cloned()
                    .collect(),
                mac_s2c: client
                    .mac_algorithms_server_to_client()
                    .into_iter()
                    .cloned()
                    .collect(),
                compression_c2s: client
                    .compression_algorithms_client_to_server()
                    .into_iter()
                    .cloned()
                    .collect(),
                compression_s2c: client
                    .compression_algorithms_server_to_client()
                    .into_iter()
                    .cloned()
                    .collect(),
            }),
        }
    }

    pub(crate) fn kex_algorithm(&self) -> &KexAlgorithm {
        &self.kex_algorithm
    }

    pub(crate) fn server_host_key_algorithm(&self) -> &HostKeyAlgorithm {
        &self.server_host_key_algorithm
    }

    pub(crate) fn encryption_algorithm_client_to_server(&self) -> &EncryptionAlgorithm {
        &self.encryption_algorithm_client_to_server
    }

    pub(crate) fn encryption_algorithm_server_to_client(&self) -> &EncryptionAlgorithm {
        &self.encryption_algorithm_server_to_client
    }

    pub(crate) fn mac_algorithm_client_to_server(&self) -> &MacAlgorithm {
        &self.mac_algorithm_client_to_server
    }

    pub(crate) fn mac_algorithm_server_to_client(&self) -> &MacAlgorithm {
        &self.mac_algorithm_server_to_client
    }

    pub(crate) fn compression_algorithm_client_to_server(&self) -> &CompressionAlgorithm {
        &self.compression_algorithm_client_to_server
    }

    pub(crate) fn compression_algorithm_server_to_client(&self) -> &CompressionAlgorithm {
        &self.compression_algorithm_server_to_client
    }
}

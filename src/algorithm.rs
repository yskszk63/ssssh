use crate::msg::Kexinit;
use crate::named::Named;

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::module_name_repetitions)]
pub enum KexAlgorithm {
    Curve25519Sha256,
}

impl Named for KexAlgorithm {
    fn name(&self) -> &'static str {
        match self {
            Self::Curve25519Sha256 => "curve25519-sha256",
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
pub enum EncryptionAlgorithm {
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
pub enum MacAlgorithm {
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
pub enum CompressionAlgorithm {
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
    pub fn to_kexinit(&self) -> Kexinit {
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
            kex_algorithms: vec![KexAlgorithm::Curve25519Sha256],
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

#[derive(Debug)]
pub enum NegotiateError {
    Missing,
}

#[derive(Debug)]
pub struct Algorithm {
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
    pub fn negotiate(client: &Kexinit, server: &Preference) -> Result<Self, NegotiateError> {
        let kex_algorithm = client
            .kex_algorithms()
            .flat_map(|e| server.kex_algorithms.iter().filter(move |s| e == s.name()))
            .next()
            .ok_or_else(|| NegotiateError::Missing)?
            .clone();

        let server_host_key_algorithm = client
            .server_host_key_algorithms()
            .flat_map(|e| {
                server
                    .server_host_key_algorithms
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next()
            .ok_or_else(|| NegotiateError::Missing)?
            .clone();

        let encryption_algorithm_client_to_server = client
            .encryption_algorithms_client_to_server()
            .flat_map(|e| {
                server
                    .encryption_algorithms_client_to_server
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next()
            .ok_or_else(|| NegotiateError::Missing)?
            .clone();

        let encryption_algorithm_server_to_client = client
            .encryption_algorithms_server_to_client()
            .flat_map(|e| {
                server
                    .encryption_algorithms_server_to_client
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next()
            .ok_or_else(|| NegotiateError::Missing)?
            .clone();

        let mac_algorithm_client_to_server = client
            .mac_algorithms_client_to_server()
            .flat_map(|e| {
                server
                    .mac_algorithms_client_to_server
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next()
            .ok_or_else(|| NegotiateError::Missing)?
            .clone();

        let mac_algorithm_server_to_client = client
            .mac_algorithms_server_to_client()
            .flat_map(|e| {
                server
                    .mac_algorithms_server_to_client
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next()
            .ok_or_else(|| NegotiateError::Missing)?
            .clone();

        let compression_algorithm_client_to_server = client
            .compression_algorithms_client_to_server()
            .flat_map(|e| {
                server
                    .compression_algorithms_client_to_server
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next()
            .ok_or_else(|| NegotiateError::Missing)?
            .clone();

        let compression_algorithm_server_to_client = client
            .compression_algorithms_server_to_client()
            .flat_map(|e| {
                server
                    .compression_algorithms_server_to_client
                    .iter()
                    .filter(move |s| e == s.name())
            })
            .next()
            .ok_or_else(|| NegotiateError::Missing)?
            .clone();

        Ok(Self {
            kex_algorithm,
            server_host_key_algorithm,
            encryption_algorithm_client_to_server,
            encryption_algorithm_server_to_client,
            mac_algorithm_client_to_server,
            mac_algorithm_server_to_client,
            compression_algorithm_client_to_server,
            compression_algorithm_server_to_client,
        })
    }

    pub fn kex_algorithm(&self) -> &KexAlgorithm {
        &self.kex_algorithm
    }

    pub fn server_host_key_algorithm(&self) -> &HostKeyAlgorithm {
        &self.server_host_key_algorithm
    }

    pub fn encryption_algorithm_client_to_server(&self) -> &EncryptionAlgorithm {
        &self.encryption_algorithm_client_to_server
    }

    pub fn encryption_algorithm_server_to_client(&self) -> &EncryptionAlgorithm {
        &self.encryption_algorithm_server_to_client
    }

    pub fn mac_algorithm_client_to_server(&self) -> &MacAlgorithm {
        &self.mac_algorithm_client_to_server
    }

    pub fn mac_algorithm_server_to_client(&self) -> &MacAlgorithm {
        &self.mac_algorithm_server_to_client
    }

    pub fn compression_algorithm_client_to_server(&self) -> &CompressionAlgorithm {
        &self.compression_algorithm_client_to_server
    }

    pub fn compression_algorithm_server_to_client(&self) -> &CompressionAlgorithm {
        &self.compression_algorithm_server_to_client
    }
}

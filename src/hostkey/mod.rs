//! Hostkey
use std::path::{Path, PathBuf};
use std::str::FromStr;

use bytes::{Buf, Bytes};
use futures::future::{ok, ready};
use futures::stream::{StreamExt as _, TryStreamExt as _};
use linked_hash_map::LinkedHashMap;
use tokio::fs::File;
use tokio::io::{AsyncBufReadExt as _, BufReader};
use tokio_stream::wrappers::LinesStream;

use crate::key::{Algorithm, Key, PublicKey};
use crate::negotiate::AlgorithmName;
use crate::pack::Unpack;
use crate::SshError;

#[derive(Debug)]
enum BuilderOperation {
    LoadFromFile(PathBuf),
    Generate,
}

#[derive(Debug, Default)]
pub(crate) struct HostKeysBuilder {
    operations: Vec<BuilderOperation>,
}

impl HostKeysBuilder {
    pub(crate) fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> &mut Self {
        self.operations
            .push(BuilderOperation::LoadFromFile(path.as_ref().to_path_buf()));
        self
    }

    pub(crate) fn generate(&mut self) -> &mut Self {
        self.operations.push(BuilderOperation::Generate);
        self
    }

    pub(crate) async fn build(&self) -> Result<HostKeys, SshError> {
        let mut hostkeys = HostKeys::new();
        for op in &self.operations {
            match op {
                BuilderOperation::LoadFromFile(path) => hostkeys.load(path).await?,
                BuilderOperation::Generate => hostkeys.generate()?,
            }
        }
        Ok(hostkeys)
    }
}

/// HostKey collection
#[derive(Debug)]
pub(crate) struct HostKeys {
    hostkeys: LinkedHashMap<Algorithm, Key>,
}

impl HostKeys {
    pub(crate) fn new() -> Self {
        Self {
            hostkeys: LinkedHashMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, hostkey: Key) {
        self.hostkeys.insert(hostkey.name(), hostkey);
    }

    pub(crate) fn lookup(&self, name: &Algorithm) -> Option<&Key> {
        self.hostkeys.get(name)
    }

    pub(crate) fn names(&self) -> Vec<Algorithm> {
        self.hostkeys.keys().cloned().collect()
    }

    pub(crate) fn generate(&mut self) -> Result<(), SshError> {
        for name in &Algorithm::defaults() {
            let hostkey = Key::gen(name)?;
            self.insert(hostkey);
        }
        Ok(())
    }

    pub(crate) async fn load<P>(&mut self, path: P) -> Result<(), SshError>
    where
        P: AsRef<Path>,
    {
        // https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.key?annotate=HEAD

        const AUTH_MAGIC: &[u8] = b"openssh-key-v1\0";
        const MARK_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----";
        const MARK_END: &str = "-----END OPENSSH PRIVATE KEY-----";

        let f = File::open(path).await?;
        let f = BufReader::new(f);

        let data = LinesStream::new(f.lines())
            .try_skip_while(|l| ok(l != MARK_BEGIN))
            .skip(1)
            .take_while(|l| ready(l.is_ok() && l.as_ref().unwrap() != MARK_END))
            .try_collect::<Vec<_>>()
            .await?
            .join("");
        let data = base64::decode(&data).map_err(|_| SshError::UnsupportedKeyFileFormat)?;
        let mut data = Bytes::from(data);

        if data.len() < AUTH_MAGIC.len() {
            return Err(SshError::UnsupportedKeyFileFormat);
        }
        let auth_magic = (&mut data).copy_to_bytes(AUTH_MAGIC.len());
        if auth_magic != AUTH_MAGIC {
            return Err(SshError::UnsupportedKeyFileFormat);
        }

        let cipher = String::unpack(&mut data)?;
        let kdf_name = String::unpack(&mut data)?;
        let kdf = String::unpack(&mut data)?;
        if (cipher.as_str(), kdf_name.as_str(), kdf.as_str()) != ("none", "none", "") {
            return Err(SshError::UnsupportedKeyFileFormat);
        }

        let num_keys = u32::unpack(&mut data)?;
        for _ in 0..num_keys {
            let _ = PublicKey::unpack(&mut data)?;
        }
        for _ in 0..num_keys {
            let mut data = Bytes::unpack(&mut data)?;
            let check1 = u32::unpack(&mut data)?;
            let check2 = u32::unpack(&mut data)?;
            if check1 != check2 {
                return Err(SshError::UnsupportedKeyFileFormat);
            }

            let alg = String::unpack(&mut data)?;
            let name = Algorithm::from_str(&alg).map_err(|e| SshError::UnknownAlgorithm(e.0))?;
            let key = Key::parse(&name, &data)?;
            self.insert(key);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn incorrect_host_key() {
        let mut hostkeys = HostKeys::new();
        hostkeys.load("Cargo.toml").await.unwrap_err();
    }
}

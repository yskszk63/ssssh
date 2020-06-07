use std::hash;
use std::str::FromStr;

use derive_builder::Builder;
use getset::Getters;
use thiserror::Error;

use crate::msg::kexinit::Kexinit;
use crate::pack::NameList;
use crate::preference::Preference;
use crate::SshError;
use crate::{comp, encrypt, hostkey, kex, mac};

#[derive(Debug, Error)]
#[error("unknown algorithm name {0}")]
pub struct UnknownNameError(pub(crate) String);

pub(crate) trait AlgorithmName:
    FromStr<Err = UnknownNameError> + AsRef<str> + Clone + PartialEq + Eq + hash::Hash
{
    fn defaults() -> Vec<Self>;

    fn to_string(&self) -> String {
        self.as_ref().to_string()
    }
}

#[derive(Debug, Builder, Getters)]
pub(crate) struct Algorithm {
    #[get = "pub(crate)"]
    kex_algorithm: kex::Algorithm,
    #[get = "pub(crate)"]
    server_host_key_algorithm: hostkey::Algorithm,
    #[get = "pub(crate)"]
    encryption_algorithm_c2s: encrypt::Algorithm,
    #[get = "pub(crate)"]
    encryption_algorithm_s2c: encrypt::Algorithm,
    #[get = "pub(crate)"]
    mac_algorithm_c2s: mac::Algorithm,
    #[get = "pub(crate)"]
    mac_algorithm_s2c: mac::Algorithm,
    #[get = "pub(crate)"]
    compression_algorithm_c2s: comp::Algorithm,
    #[get = "pub(crate)"]
    compression_algorithm_s2c: comp::Algorithm,
}

fn decide<N>(l: &[N], r: &NameList) -> Result<N, SshError>
where
    N: AlgorithmName,
{
    let found = r
        .iter()
        .flat_map(|r| l.iter().filter(move |l| r.as_str() == l.as_ref()))
        .next();

    found.map(ToOwned::to_owned).ok_or_else(|| {
        SshError::NegotiateNotMatched(r.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(","))
    })
}

pub(crate) fn negotiate(
    c_kexinit: &Kexinit,
    preference: &Preference,
) -> Result<Algorithm, SshError> {
    let mut builder = AlgorithmBuilder::default();

    let kex_algorithm = decide(preference.kex_algorithms(), c_kexinit.kex_algorithms())?;
    builder.kex_algorithm(kex_algorithm);

    let server_host_key_algorithm = decide(
        &preference.hostkeys().names(),
        c_kexinit.server_host_key_algorithms(),
    )?;
    builder.server_host_key_algorithm(server_host_key_algorithm);

    let encryption_algorithm_c2s = decide(
        preference.encryption_algorithms(),
        c_kexinit.encryption_algorithms_c2s(),
    )?;
    builder.encryption_algorithm_c2s(encryption_algorithm_c2s);

    let encryption_algorithm_s2c = decide(
        preference.encryption_algorithms(),
        c_kexinit.encryption_algorithms_s2c(),
    )?;
    builder.encryption_algorithm_s2c(encryption_algorithm_s2c);

    let mac_algorithm_c2s = decide(preference.mac_algorithms(), c_kexinit.mac_algorithms_c2s())?;
    builder.mac_algorithm_c2s(mac_algorithm_c2s);

    let mac_algorithm_s2c = decide(preference.mac_algorithms(), c_kexinit.mac_algorithms_s2c())?;
    builder.mac_algorithm_s2c(mac_algorithm_s2c);

    let compression_algorithm_c2s = decide(
        preference.compression_algorithms(),
        c_kexinit.compression_algorithms_c2s(),
    )?;
    builder.compression_algorithm_c2s(compression_algorithm_c2s);

    let compression_algorithm_s2c = decide(
        preference.compression_algorithms(),
        c_kexinit.compression_algorithms_s2c(),
    )?;
    builder.compression_algorithm_s2c(compression_algorithm_s2c);

    Ok(builder.build().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list<'a, V: AsRef<[&'a str]>>(v: V) -> NameList {
        v.as_ref().into_iter().map(ToOwned::to_owned).collect()
    }

    #[test]
    fn test_decide() {
        use mac::Algorithm::*;

        let r = decide(&[HmacSha1], &list(["hmac-sha1"]));
        assert_eq!(r.unwrap(), HmacSha1);

        let r = decide(&[HmacSha1], &list(["hmac-sha2-256"]));
        assert!(matches!(r, Err(SshError::NegotiateNotMatched(..))));

        let r = decide(&[] as &[mac::Algorithm], &list([]));
        assert!(matches!(r, Err(SshError::NegotiateNotMatched(..))));

        let r = decide(&[HmacSha1], &list(["hmac-sha2-256", "hmac-sha1"]));
        assert_eq!(r.unwrap(), HmacSha1);

        let r = decide(
            &[HmacSha1, HmacSha256],
            &list(["hmac-sha2-256", "hmac-sha1"]),
        );
        assert_eq!(r.unwrap(), HmacSha256);

        let r = decide(&[HmacSha1], &list(["hmac-sha2-256", "none"]));
        assert!(matches!(r, Err(SshError::NegotiateNotMatched(..))));
    }

    #[test]
    fn test_negotiate() {
        let c_kexinit = crate::msg::kexinit::KexinitBuilder::default()
            .cookie(0)
            .kex_algorithms(list(["curve25519-sha256"]))
            .server_host_key_algorithms(list(["ssh-ed25519"]))
            .encryption_algorithms_c2s(list(["aes256-ctr"]))
            .encryption_algorithms_s2c(list(["aes256-ctr"]))
            .mac_algorithms_c2s(list(["hmac-sha2-256"]))
            .mac_algorithms_s2c(list(["hmac-sha2-256"]))
            .compression_algorithms_c2s(list(["none"]))
            .compression_algorithms_s2c(list(["none"]))
            .languages_c2s(list([""]))
            .languages_s2c(list([""]))
            .first_kex_packet_follows(false)
            .build()
            .unwrap();

        let preference = crate::preference::PreferenceBuilder::default()
            .build()
            .unwrap();

        negotiate(&c_kexinit, &preference).unwrap();
    }
}

use derive_builder::Builder;
use getset::Getters;
use thiserror::Error;

use crate::msg::kexinit::Kexinit;
use crate::pack::NameList;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum NegotiateError {
    #[error("not matched {0:?}")]
    NotMatched(String),
}

#[derive(Debug, Builder, Getters)]
pub(crate) struct Algorithm {
    #[get = "pub(crate)"]
    kex_algorithm: String,
    #[get = "pub(crate)"]
    server_host_key_algorithm: String,
    #[get = "pub(crate)"]
    encryption_algorithm_c2s: String,
    #[get = "pub(crate)"]
    encryption_algorithm_s2c: String,
    #[get = "pub(crate)"]
    mac_algorithm_c2s: String,
    #[get = "pub(crate)"]
    mac_algorithm_s2c: String,
    #[get = "pub(crate)"]
    compression_algorithm_c2s: String,
    #[get = "pub(crate)"]
    compression_algorithm_s2c: String,
}

fn decide(l: &NameList, r: &NameList) -> Result<String, NegotiateError> {
    let found = r
        .iter()
        .flat_map(|r| l.iter().filter(move |l| r == *l))
        .next();

    found.map(ToOwned::to_owned).ok_or_else(|| {
        NegotiateError::NotMatched(r.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(","))
    })
}

pub(crate) fn negotiate(
    c_kexinit: &Kexinit,
    s_kexinit: &Kexinit,
) -> Result<Algorithm, NegotiateError> {
    let mut builder = AlgorithmBuilder::default();

    let kex_algorithm = decide(s_kexinit.kex_algorithms(), c_kexinit.kex_algorithms())?;
    builder.kex_algorithm(kex_algorithm);

    let server_host_key_algorithm = decide(
        s_kexinit.server_host_key_algorithms(),
        c_kexinit.server_host_key_algorithms(),
    )?;
    builder.server_host_key_algorithm(server_host_key_algorithm);

    let encryption_algorithm_c2s = decide(
        s_kexinit.encryption_algorithms_c2s(),
        c_kexinit.encryption_algorithms_c2s(),
    )?;
    builder.encryption_algorithm_c2s(encryption_algorithm_c2s);

    let encryption_algorithm_s2c = decide(
        s_kexinit.encryption_algorithms_s2c(),
        c_kexinit.encryption_algorithms_s2c(),
    )?;
    builder.encryption_algorithm_s2c(encryption_algorithm_s2c);

    let mac_algorithm_c2s = decide(
        s_kexinit.mac_algorithms_c2s(),
        c_kexinit.mac_algorithms_c2s(),
    )?;
    builder.mac_algorithm_c2s(mac_algorithm_c2s);

    let mac_algorithm_s2c = decide(
        s_kexinit.mac_algorithms_s2c(),
        c_kexinit.mac_algorithms_s2c(),
    )?;
    builder.mac_algorithm_s2c(mac_algorithm_s2c);

    let compression_algorithm_c2s = decide(
        s_kexinit.compression_algorithms_c2s(),
        c_kexinit.compression_algorithms_c2s(),
    )?;
    builder.compression_algorithm_c2s(compression_algorithm_c2s);

    let compression_algorithm_s2c = decide(
        s_kexinit.compression_algorithms_s2c(),
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
        let r = decide(&list(["a"]), &list(["a"]));
        assert_eq!(r, Ok("a".into()));

        let r = decide(&list(["a"]), &list(["b"]));
        assert!(matches!(r, Err(NegotiateError::NotMatched(..))));

        let r = decide(&list([]), &list([]));
        assert!(matches!(r, Err(NegotiateError::NotMatched(..))));

        let r = decide(&list(["a"]), &list(["b", "a"]));
        assert_eq!(r, Ok("a".into()));

        let r = decide(&list(["a", "b"]), &list(["b", "a"]));
        assert_eq!(r, Ok("b".into()));

        let r = decide(&list(["a"]), &list(["b", "c"]));
        assert!(matches!(r, Err(NegotiateError::NotMatched(..))));
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
        let s_kexinit = crate::msg::kexinit::KexinitBuilder::default()
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

        negotiate(&c_kexinit, &s_kexinit).unwrap();
    }
}

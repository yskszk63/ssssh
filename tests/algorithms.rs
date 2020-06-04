use futures::future::ok;
use futures::prelude::*;
use tokio::process::Command;

use ssssh::{Handlers, ServerBuilder};

const CIPHERS: &'static [&'static str] = &["aes256-ctr"];

const KEXS: &'static [&'static str] = &[
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha256",
    "curve25519-sha256",
];

const KEYS: &'static [&'static str] = &["ssh-ed25519", "ssh-rsa"];

const MACS: &'static [&'static str] = &["hmac-sha1", "hmac-sha2-256"];

const CKEYS: &'static [&'static str] = &["tests/ed25519", "tests/rsa"];

fn algorithms() -> Vec<(
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
)> {
    let mut result = vec![];
    for cipher in CIPHERS {
        for kex in KEXS {
            for key in KEYS {
                for mac in MACS {
                    for ckey in CKEYS {
                        result.push((*cipher, *kex, *key, *mac, *ckey));
                    }
                }
            }
        }
    }
    result
}

#[tokio::test]
async fn test() {
    for (cipher, kex, key, mac, ckey) in algorithms() {
        do_test(cipher, kex, key, mac, ckey).await
    }
}

async fn do_test(cipher: &str, kex: &str, key: &str, mac: &str, ckey: &str) {
    let mut server = ServerBuilder::default().build("[::1]:2222").await.unwrap();

    let mut handlers = Handlers::<anyhow::Error>::new();
    handlers.on_auth_publickey(|_, _, _| ok(true).boxed());
    handlers.on_channel_shell(|_, _, _| ok(0).boxed());

    let proc = Command::new("ssh")
        .env_clear()
        .arg("-oStrictHostKeyChecking=no")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg(format!("-oCiphers={}", cipher))
        .arg(format!("-oKexAlgorithms={}", kex))
        .arg(format!("-oHostKeyAlgorithms={}", key))
        .arg(format!("-oMACs={}", mac))
        .arg(format!("-i{}", ckey))
        .arg("-p2222")
        .arg("::1")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();

    let connection = server.try_next().await.unwrap().unwrap();
    let connection = connection.accept().await.unwrap();
    connection.run(handlers).await.unwrap();

    let output = proc.wait_with_output().await.unwrap();
    assert_eq!(output.status.code(), Some(0));
}
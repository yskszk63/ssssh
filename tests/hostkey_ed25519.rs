use futures::future::ok;
use futures::prelude::*;
use tokio::process::Command;

use ssssh::{Handlers, ServerBuilder};

#[tokio::test]
async fn ed25519() {
    simple_logger::SimpleLogger::new().init().ok();

    let mut server = ServerBuilder::default()
        .hostkeys_from_path("tests/ed25519")
        .build("[::1]:2222")
        .await
        .unwrap();

    let mut handlers = Handlers::<anyhow::Error>::new();
    handlers.on_auth_none(|_| ok(true).boxed());
    handlers.on_channel_shell(|_, _, _| ok(0).boxed());

    let proc = Command::new("ssh")
        .env_clear()
        .arg("-oStrictHostKeyChecking=no")
        .arg("-oUserKnownHostsFile=/dev/null")
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
    assert!(output.status.success());
}

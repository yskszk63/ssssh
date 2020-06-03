use tokio::process::Command;
use futures::prelude::*;
use futures::future::ok;

use ssssh::{ServerBuilder, Handlers};

#[tokio::test]
async fn test() {
    let mut server = ServerBuilder::default()
        .build("[::1]:2222")
        .await.unwrap();

    let mut handlers = Handlers::<anyhow::Error>::new();
    handlers.on_auth_none(|_| ok(true).boxed());
    handlers.on_channel_shell(|_, _, _| ok(0).boxed());

    let proc = Command::new("ssh")
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

use std::process::Stdio;

use futures::future::ok;
use futures::prelude::*;
use tokio::io;
use tokio::process::Command;

use ssssh::{Handlers, ServerBuilder};

#[tokio::test]
async fn shell() {
    simple_logger::SimpleLogger::new().init().ok();

    let mut server = ServerBuilder::default().build("[::1]:2222").await.unwrap();

    let mut handlers = Handlers::<anyhow::Error>::new();
    handlers.on_auth_none(|_| ok(true).boxed());
    handlers.on_channel_shell(|_| {
        async move { Err(io::Error::new(io::ErrorKind::Other, "").into()) }.boxed()
    });

    let proc = Command::new("ssh")
        .env_clear()
        .arg("-oStrictHostKeyChecking=no")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg("-p2222")
        .arg("-q")
        .arg("::1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();

    let connection = server.try_next().await.unwrap().unwrap();
    let connection = connection.accept().await.unwrap();
    connection.run(handlers).await.unwrap_err();

    let output = proc.wait_with_output().await.unwrap();
    assert!(!output.status.success());
}

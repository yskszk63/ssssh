use std::time::Duration;

use futures::future::ok;
use futures::future::FutureExt as _;
use futures::stream::TryStreamExt as _;

use ssssh::ServerBuilder;
use ssssh::{Handlers, PasswordResult};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut server = ServerBuilder::default()
        .timeout(Duration::from_secs(5))
        .build("[::1]:2222")
        .await?;

    use tokio::process::Command;
    let mut proc = Command::new("ssh")
        .arg("-oStrictHostKeyChecking=no")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg("-p2222")
        .arg("-vvv")
        .arg("::1")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .unwrap();

    if let Some(connection) = server.try_next().await? {
        let connection = connection.accept().await?;

        let mut handlers = Handlers::<anyhow::Error>::new();

        handlers.on_auth_password(|_, _| {
            ok(PasswordResult::PasswordChangeRequired(
                "please change password!".into(),
            ))
            .boxed()
        });
        handlers.on_auth_change_password(|_, _, _| {
            ok(PasswordResult::PasswordChangeRequired(
                "please change password!".into(),
            ))
            .boxed()
        });

        connection.run(handlers).await?;
    }
    proc.wait().await.unwrap();

    Ok(())
}

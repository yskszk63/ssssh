use std::time::Duration;

use async_trait::async_trait;
use futures::stream::TryStreamExt as _;

use ssssh::ServerBuilder;
use ssssh::{Handlers, PasswordResult};

struct MyHandler;

#[async_trait]
impl Handlers for MyHandler {
    type Err = anyhow::Error;

    async fn handle_auth_password_change(
        &mut self,
        _username: &str,
        _oldpassword: &str,
        _newpassword: &str,
    ) -> Result<PasswordResult, Self::Err> {
        Ok(PasswordResult::PasswordChangeRequired(
            "password expired".into(),
        ))
    }

    async fn handle_auth_password(
        &mut self,
        _username: &str,
        _password: &str,
    ) -> Result<PasswordResult, Self::Err> {
        Ok(PasswordResult::PasswordChangeRequired(
            "password expired".into(),
        ))
    }
}

#[tokio::main(basic_scheduler)]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    use tokio::process::Command;
    let proc = Command::new("ssh")
        .arg("-oStrictHostKeyChecking=no")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg("-p2222")
        .arg("-vvv")
        .arg("::1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();

    let mut server = ServerBuilder::default()
        .timeout(Duration::from_secs(5))
        .build("[::1]:2222")
        .await?;

    if let Some(connection) = server.try_next().await? {
        let connection = connection.await?;
        connection.run(MyHandler).await?;
    }
    proc.await.unwrap();

    Ok(())
}

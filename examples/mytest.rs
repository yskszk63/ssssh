use std::time::Duration;

use async_trait::async_trait;

use ssssh::AuthHandle;
use ssssh::ServerBuilder;
use ssssh::{Handler, PasswordAuth, PasswordChangeAuth};

struct MyHandler;

#[async_trait]
impl Handler for MyHandler {
    type Error = failure::Error;

    async fn auth_password_change(
        &mut self,
        _username: &str,
        _oldpassword: &str,
        _newpassword: &str,
        _handle: &AuthHandle,
    ) -> Result<PasswordChangeAuth, Self::Error> {
        Ok(PasswordChangeAuth::ChangePasswdreq(
            "password expired".into(),
        ))
    }

    async fn auth_password(
        &mut self,
        _username: &str,
        _password: &[u8],
        handle: &AuthHandle,
    ) -> Result<PasswordAuth, Self::Error> {
        let mut handle = handle.clone();
        handle.send_banner("Allow Logged in", "").await.unwrap();
        Ok(PasswordAuth::ChangePasswdreq("password expired".into()))
    }
}

#[tokio::main(basic_scheduler)]
async fn main() {
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

    let builder = ServerBuilder::default();
    let mut server = builder
        .timeout(Duration::from_secs(5))
        .build("[::1]:2222".parse().unwrap(), |_| MyHandler)
        .await
        .unwrap();
    match server.accept().await {
        Ok(connection) => {
            connection.run().await.unwrap();
        }
        Err(e) => {
            eprintln!("{}", e);
        }
    }
    proc.await.unwrap();
}

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

#[tokio::main(single_thread)]
async fn main() {
    env_logger::init();

    tokio::executor::spawn(async {
        use tokio_net::process::Command;
        Command::new("ssh")
            .arg("-oStrictHostKeyChecking=no")
            .arg("-oUserKnownHostsFile=/dev/null")
            .arg("-p2222")
            .arg("-vvv")
            .arg("::1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap()
            .await
            .unwrap();
        println!("DONE.");
    });

    let builder = ServerBuilder::default();
    let mut server = builder.build("[::1]:2222".parse().unwrap(), || MyHandler);
    loop {
        match server.accept().await {
            Ok(connection) => {
                tokio::spawn(async { connection.run().await.unwrap() });
            }
            Err(e) => {
                eprintln!("{}", e);
            }
        }
    }
}

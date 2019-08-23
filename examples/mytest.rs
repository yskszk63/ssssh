use futures::future::{BoxFuture, FutureExt as _};

use ssssh::ServerBuilder;
use ssssh::{AuthHandle, ChannelHandle};
use ssssh::{Handler, PasswordAuth, PasswordChangeAuth};

struct MyHandler;

impl Handler for MyHandler {
    type Error = failure::Error;

    fn auth_password_change(
        &mut self,
        _username: &str,
        _oldpassword: &str,
        _newpassword: &str,
        _handle: &AuthHandle,
    ) -> BoxFuture<Result<PasswordChangeAuth, Self::Error>> {
        async move {
            Ok(PasswordChangeAuth::ChangePasswdreq(
                "password expired".into(),
            ))
        }
            .boxed()
    }

    fn auth_password(
        &mut self,
        _username: &str,
        password: &str,
        handle: &AuthHandle,
    ) -> BoxFuture<Result<PasswordAuth, Self::Error>> {
        dbg!(password);
        let mut handle = handle.clone();
        async move {
            handle.send_banner("Allow Logged in", "").await;
            Ok(PasswordAuth::ChangePasswdreq("password expired".into()))
        }
            .boxed()
    }

    fn channel_open_session(
        &mut self,
        _handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        async {
            //let e: Result<(), _> = Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe)).into();
            //Ok(e?)
            Ok(())
        }
            .boxed()
    }

    fn channel_shell_request(
        &mut self,
        handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        let mut handle = handle.clone();
        async move {
            tokio::spawn(async move {
                handle.send_data("Hello World!").await;
                handle.send_data("Hello World!").await;
                handle.send_data("Hello World!").await;
                handle.send_data("Hello World!").await;
                handle.send_data("Hello World!").await;
                handle.send_data("Hello World!").await;
                handle.send_extended_data("Hello World!").await;
                handle.send_eof().await;
                handle.send_exit_status(0).await;
                handle.send_close().await;
            });
            Ok(())
        }
            .boxed()
    }

    fn channel_data(
        &mut self,
        data: &[u8],
        handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        let mut handle = handle.clone();
        let data = bytes::Bytes::from(data);
        async move {
            handle.send_data(data).await;
            Ok(())
        }
            .boxed()
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
            //.stdout(std::process::Stdio::null())
            //.stderr(std::process::Stdio::null())
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

#![feature(async_await)]

use futures::future::{BoxFuture, FutureExt as _};

use ssssh::ServerBuilder;
use ssssh::{Auth, Handler};
use ssssh::{AuthHandle, ChannelHandle};

struct MyHandler;

impl Handler for MyHandler {
    type Error = failure::Error;

    fn auth_password(
        &mut self,
        _username: &str,
        _password: &[u8],
        handle: &AuthHandle,
    ) -> BoxFuture<Result<Auth, Self::Error>> {
        let mut handle = handle.clone();
        async move {
            handle.send_banner("Allow Logged in", "").await;
            Ok(Auth::Accept)
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
        }.boxed()
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
    /*

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
        }.boxed()
    }
    */
}

#[tokio::main(single_thread)]
async fn main() {
    tokio::executor::spawn(async {
        use std::process::Command;
        use tokio_process::CommandExt as _;
        Command::new("ssh")
            .arg("-oStrictHostKeyChecking=no")
            .arg("-oUserKnownHostsFile=/dev/null")
            .arg("-p2222")
            .arg("-vvv")
            .arg("::1")
            //.stdout(std::process::Stdio::null())
            //.stderr(std::process::Stdio::null())
            .spawn_async()
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
                tokio::spawn(connection.run());
            }
            Err(e) => {
                eprintln!("{}", e);
            }
        }
    }
}

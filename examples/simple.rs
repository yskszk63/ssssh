#![feature(async_await)]

use futures::future::{BoxFuture, FutureExt as _};

use ssssh::ServerBuilder;
use ssssh::{Auth, AuthError, AuthHandler, ChannelError, ChannelHandler};
use ssssh::{AuthHandle, ChannelHandle};

struct Handler;

impl AuthHandler for Handler {
    type Error = AuthError;

    fn handle_password(
        &mut self,
        _username: &str,
        _password: &[u8],
        _handle: AuthHandle,
    ) -> BoxFuture<Result<Auth, Self::Error>> {
        async { Ok(Auth::Accept) }.boxed()
    }
}

impl ChannelHandler for Handler {
    type Error = ChannelError;

    fn handle_shell_request(
        &mut self,
        _session_id: u32,
        mut handle: ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        async {
            tokio::spawn(async move {
                handle.send_data("Hello World!").await;
                handle.send_data("Hello World!").await;
                handle.send_data("Hello World!").await;
                handle.send_data("Hello World!").await;
                handle.send_data("Hello World!").await;
                handle.send_data("Hello World!").await;
                handle.send_eof().await;
                handle.send_close().await;
            });
            Ok(())
        }
            .boxed()
    }
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
    });

    let builder = ServerBuilder::default();
    let mut server = builder.build("[::1]:2222".parse().unwrap(), || Handler, || Handler);
    loop {
    let connection = server.accept().await;
    //connection.run().await;
    tokio::spawn(connection.run());
    }
}

use futures::future::{BoxFuture, FutureExt as _};

use ssssh::ServerBuilder;
use ssssh::{AuthHandle, ChannelHandle, Handler, PasswordAuth};

struct MyHandler;

impl Handler for MyHandler {
    type Error = failure::Error;

    fn auth_password(
        &mut self,
        _username: &str,
        _password: &str,
        _handle: &AuthHandle,
    ) -> BoxFuture<Result<PasswordAuth, Self::Error>> {
        async move { Ok(PasswordAuth::Accept) }.boxed()
    }

    fn channel_shell_request(
        &mut self,
        handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        let mut handle = handle.clone();
        async move {
            tokio::spawn(async move {
                handle.send_data("Hello World!").await.unwrap();
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
            handle.send_data(data).await.unwrap();
            Ok(())
        }
            .boxed()
    }
}

#[tokio::main(single_thread)]
async fn main() {
    env_logger::init();

    let mut server = ServerBuilder::default().build("[::1]:2222".parse().unwrap(), || MyHandler);
    loop {
        match server.accept().await {
            Ok(connection) => {
                tokio::spawn(async { println!("{:?}", connection.run().await) });
            }
            Err(e) => {
                eprintln!("{}", e);
            }
        }
    }
}

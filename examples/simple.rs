use std::time::Duration;

use async_trait::async_trait;
use bytes::buf::Buf as _;

use ssssh::{AuthHandle, ChannelHandle, Handler, PasswordAuth, ServerBuilder};

struct MyHandler;

#[async_trait]
impl Handler for MyHandler {
    type Error = failure::Error;

    async fn auth_password(
        &mut self,
        _username: &str,
        _password: &[u8],
        _handle: &AuthHandle,
    ) -> Result<PasswordAuth, Self::Error> {
        Ok(PasswordAuth::Accept)
    }

    async fn channel_shell_request(&mut self, handle: &ChannelHandle) -> Result<(), Self::Error> {
        let mut handle = handle.clone();
        tokio::spawn(async move {
            handle.send_data("Hello World!").await.unwrap();
        });
        Ok(())
    }

    async fn channel_data(
        &mut self,
        mut data: &[u8],
        handle: &ChannelHandle,
    ) -> Result<(), Self::Error> {
        let mut handle = handle.clone();
        let data = data.to_bytes();
        handle.send_data(data.clone()).await?;
        Ok(())
    }
}

#[tokio::main(basic_scheduler)]
async fn main() {
    env_logger::init();

    let mut server = ServerBuilder::default()
        .timeout(Duration::from_secs(5))
        .build("[::1]:2222".parse().unwrap(), |_| MyHandler)
        .await
        .unwrap();
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

use async_trait::async_trait;

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
        data: &[u8],
        handle: &ChannelHandle,
    ) -> Result<(), Self::Error> {
        let mut handle = handle.clone();
        handle.send_data(data).await?;
        Ok(())
    }
}

#[tokio::main(single_thread)]
async fn main() {
    env_logger::init();

    let mut server = ServerBuilder::default()
        .build("[::1]:2222".parse().unwrap(), || MyHandler)
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

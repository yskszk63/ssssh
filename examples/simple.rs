use std::time::Duration;

use async_trait::async_trait;
use futures::future::{BoxFuture, FutureExt as _, TryFutureExt as _};
use futures::stream::TryStreamExt as _;
use ssssh::{Handlers, PasswordResult, ServerBuilder};
use tokio::io::{AsyncRead, AsyncWrite};

struct MyHandler;

#[async_trait]
impl Handlers for MyHandler {
    type Err = anyhow::Error;

    async fn handle_auth_password(
        &mut self,
        _username: &str,
        _password: &str,
    ) -> Result<PasswordResult, Self::Err> {
        Ok(PasswordResult::Ok)
    }

    fn handle_channel_shell<I, O, E>(
        &mut self,
        mut stdin: I,
        mut stdout: O,
        _stderr: E,
    ) -> BoxFuture<'static, Result<u32, Self::Err>>
    where
        I: AsyncRead + Send + Unpin + 'static,
        O: AsyncWrite + Send + Unpin + 'static,
        E: AsyncWrite + Send + Unpin + 'static,
    {
        async move {
            tokio::io::copy(&mut stdin, &mut stdout).await?;
            Ok(0)
        }
        .boxed()
    }
}

#[tokio::main(basic_scheduler)]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut server = ServerBuilder::default()
        .timeout(Duration::from_secs(5))
        .build("[::1]:2222")
        .await?;

    while let Some(conn) = server.try_next().await? {
        tokio::spawn(
            async move {
                let conn = conn.accept().await?;
                conn.run(MyHandler).await?;
                Ok::<_, anyhow::Error>(())
            }
            .map_err(|e| println!("{}", e)),
        );
    }
    Ok(())
}

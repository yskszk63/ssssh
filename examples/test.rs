use std::ffi::OsString;

use futures::future::{BoxFuture, FutureExt as _, TryFutureExt as _};
use futures::stream::TryStreamExt as _;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt as _};

use ssssh::Handlers;
use ssssh::PasswordResult;
use ssssh::ServerBuilder;

struct MyHandler;

#[async_trait::async_trait]
impl Handlers for MyHandler {
    type Err = anyhow::Error;

    async fn handle_auth_none(&mut self, _username: &str) -> Result<bool, Self::Err> {
        //Ok(true)
        Ok(false)
    }

    async fn handle_auth_publickey(
        &mut self,
        username: &str,
        algorithm: &str,
        publickey: &str,
    ) -> Result<bool, Self::Err> {
        println!("PUBLICKEY {} {} {}", username, algorithm, publickey);
        Ok(true)
    }

    async fn handle_auth_hostbased(
        &mut self,
        username: &str,
        algorithm: &str,
        hostname: &str,
        publickey: &str,
    ) -> Result<bool, Self::Err> {
        println!(
            "HOSTBASED {} {} {} {}",
            username, algorithm, hostname, publickey
        );
        Ok(true)
    }

    async fn handle_auth_password(
        &mut self,
        _username: &str,
        _password: &str,
    ) -> Result<PasswordResult, Self::Err> {
        Ok(PasswordResult::Failure)
    }

    async fn handle_auth_password_change(
        &mut self,
        _username: &str,
        _old_password: &str,
        _new_password: &str,
    ) -> Result<PasswordResult, Self::Err> {
        Ok(PasswordResult::Failure)
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
            stdout.shutdown().await?;
            Ok(0)
        }
        .boxed()
    }

    fn handle_channel_exec<I, O, E>(
        &mut self,
        stdin: I,
        mut stdout: O,
        stderr: E,
        _prog: OsString,
    ) -> BoxFuture<'static, Result<u32, Self::Err>>
    where
        I: AsyncRead + Send + Unpin + 'static,
        O: AsyncWrite + Send + Unpin + 'static,
        E: AsyncWrite + Send + Unpin + 'static,
    {
        drop(stdin);
        drop(stderr);

        async move {
            stdout.write(b"Hello, world! ").await?;
            stdout.shutdown().await?;
            Ok(0)
        }
        .boxed()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut server = ServerBuilder::new().build("[::1]:2222").await?;
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

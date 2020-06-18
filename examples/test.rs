use futures::future::ok;
use futures::future::{FutureExt as _, TryFutureExt as _};
use futures::stream::TryStreamExt as _;
use tokio::io::AsyncWriteExt as _;

use ssssh::Handlers;
use ssssh::PasswordResult;
use ssssh::ServerBuilder;
use ssssh::SshOutput;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut server = ServerBuilder::default()
        .hostkeys_from_path("tests/ed25519")
        .hostkeys_from_path("tests/rsa")
        .build("[::1]:2222")
        .await?;
    while let Some(conn) = server.try_next().await? {
        tokio::spawn(
            async move {
                let conn = conn.accept().await?;

                let mut handlers = Handlers::<anyhow::Error>::new();

                handlers.on_auth_none(|_| ok(false).boxed());
                handlers.on_auth_publickey(|_, _, _| ok(false).boxed());
                handlers.on_auth_password(|_, _| {
                    ok(PasswordResult::PasswordChangeRequired(
                        "please change password!".into(),
                    ))
                    .boxed()
                });
                handlers.on_auth_change_password(|_, _, _| ok(PasswordResult::Failure).boxed());
                handlers.on_auth_hostbased(|_, _, _, _| ok(true).boxed());

                handlers.on_channel_shell(|mut stdin, mut stdout: SshOutput, _| {
                    async move {
                        tokio::io::copy(&mut stdin, &mut stdout).await?;
                        stdout.shutdown().await?;
                        Ok(0)
                    }
                    .boxed()
                });

                handlers.on_channel_exec(|_, mut stdout: SshOutput, _, _| {
                    async move {
                        stdout.write(b"Hello, World!").await?;
                        stdout.shutdown().await?;
                        Ok(0)
                    }
                    .boxed()
                });

                handlers.on_channel_direct_tcpip(|_, mut stdout: SshOutput| {
                    async move {
                        stdout.write(b"Hello, World!").await?;
                        stdout.shutdown().await?;
                        Ok(())
                    }
                    .boxed()
                });

                conn.run(handlers).await?;
                Ok::<_, anyhow::Error>(())
            }
            .map_err(|e| println!("{}", e)),
        );
    }

    Ok(())
}

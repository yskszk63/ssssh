use std::os::unix::io::{FromRawFd, IntoRawFd};
use std::process::Stdio;

use futures::future::ok;
use futures::future::{FutureExt as _, TryFutureExt as _};
use futures::stream::TryStreamExt as _;
use tokio::process::Command;

use ssssh::Handlers;
use ssssh::ServerBuilder;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut server = ServerBuilder::default().build("[::1]:2222").await?;
    while let Some(conn) = server.try_next().await? {
        tokio::spawn(
            async move {
                let conn = conn.accept().await?;
                let mut handlers = Handlers::<anyhow::Error>::new();

                handlers.on_auth_none(|_| ok(true).boxed());
                handlers.on_channel_shell(|mut ctx: ssssh::SessionContext| {
                    let (stdin, stdout, stderr) = ctx.take_stdio().unwrap();
                    async move {
                        let stdin = unsafe { Stdio::from_raw_fd(stdin.into_raw_fd()) };
                        let stdout = unsafe { Stdio::from_raw_fd(stdout.into_raw_fd()) };
                        let stderr = unsafe { Stdio::from_raw_fd(stderr.into_raw_fd()) };
                        let status = Command::new("bash")
                            .stdin(stdin)
                            .stdout(stdout)
                            .stderr(stderr)
                            .status()
                            .await?;
                        Ok(status.code().unwrap_or(255) as u32)
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

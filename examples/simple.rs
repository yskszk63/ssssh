/// simple echo server (`examples/simple.rs`)
use std::time::Duration;

use futures::future::{ok, FutureExt as _, TryFutureExt as _};
use futures::stream::TryStreamExt as _;
use ssssh::{Handlers, ServerBuilder};

#[tokio::main(flavor = "current_thread")]
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

                let mut handlers = Handlers::<anyhow::Error>::new();

                handlers.on_auth_none(|_| ok(true).boxed());
                handlers.on_channel_shell(|mut stdin, mut stdout, _| {
                    async move {
                        tokio::io::copy(&mut stdin, &mut stdout).await?;
                        Ok(0)
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

use std::collections::HashMap;
use std::env;
use std::path::Path;
use std::sync::Arc;
/// simple public key auth
use std::time::Duration;

use futures::future::{FutureExt as _, TryFutureExt as _};
use futures::stream::TryStreamExt as _;
use ssssh::{authorized_keys::AuthorizedKeys, Handlers, ServerBuilder};
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut server = ServerBuilder::default()
        .timeout(Duration::from_secs(5))
        .build("[::1]:2222")
        .await?;

    let home = env::var("HOME").unwrap();
    let path = Path::new(&home).join(".ssh/authorized_keys");
    let mut file = File::open(path).await?;
    let authorized_keys = AuthorizedKeys::parse(&mut file).await?;
    let authorized_keys = authorized_keys
        .into_iter()
        .map(|k| (k.publickey().clone(), k))
        .collect::<HashMap<_, _>>();
    let authorized_keys = Arc::new(Mutex::new(authorized_keys));

    while let Some(conn) = server.try_next().await? {
        let authorized_keys = authorized_keys.clone();
        tokio::spawn(
            async move {
                let conn = conn.accept().await?;

                let mut handlers = Handlers::<anyhow::Error>::new();

                handlers.on_auth_publickey(move |_, publickey| {
                    let authorized_keys = authorized_keys.clone();
                    async move {
                        let authorized_keys = authorized_keys.clone();
                        let authorized_keys = authorized_keys.lock().await;
                        Ok(authorized_keys.contains_key(&publickey))
                    }
                    .boxed()
                });
                handlers.on_channel_shell(|mut ctx: ssssh::SessionContext| {
                    let (_, mut stdout, _) = ctx.take_stdio().unwrap();
                    async move {
                        stdout.write_all(&b"publickey OK"[..]).await?;
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

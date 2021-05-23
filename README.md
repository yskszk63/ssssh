# ssssh

SSH Server library by Rust.
This is my hobby project.

[docs](https://yskszk63.github.io/ssssh/ssssh/)

## example

simple echo server

~~~rust
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
                handlers.on_channel_shell(|mut ctx: ssssh::SessionContext| {
                    let (mut stdin, mut stdout, _) = ctx.take_stdio().unwrap();
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
~~~


### License

Licensed under either of
* Apache License, Version 2.0
  ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license
  ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.!

License: MIT OR Apache-2.0

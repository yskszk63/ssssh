use std::net::TcpStream;
use std::path::PathBuf;

use futures::future::ok;
use futures::prelude::*;
use ssh2::Session;
use ssssh::{authorized_keys::AuthorizedKeys, Handlers, ServerBuilder};
use tokio::fs::File;

#[tokio::test]
async fn hostbased() {
    simple_logger::SimpleLogger::new().init().ok();

    let mut server = ServerBuilder::default().build("[::1]:2222").await.unwrap();

    let mut handlers = Handlers::<anyhow::Error>::new();
    handlers.on_auth_hostbased(|_, _, publickey| {
        async move {
            let mut file = File::open("tests/rsa.pub").await?;
            let authorized_keys = AuthorizedKeys::parse(&mut file).await?;
            for key in authorized_keys {
                if key.publickey() == &publickey {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        .boxed()
    });
    handlers.on_channel_shell(|_| ok(0).boxed());

    let task = tokio::task::spawn_blocking(|| {
        let connection = TcpStream::connect("[::1]:2222").unwrap();
        let mut session = Session::new().unwrap();
        session.set_tcp_stream(connection);
        session.handshake().unwrap();

        session
            .userauth_hostbased_file(
                "foo",
                &PathBuf::from("tests/rsa.pub"),
                &PathBuf::from("tests/rsa"),
                None,
                "bar",
                None,
            )
            .unwrap();
        assert!(session.authenticated());
    });

    let connection = server.try_next().await.unwrap().unwrap();
    let connection = connection.accept().await.unwrap();
    connection.run(handlers).await.unwrap();

    task.await.unwrap();
}

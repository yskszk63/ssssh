use std::net::TcpStream;

use futures::future::ok;
use futures::prelude::*;
use ssh2::Session;
use ssssh::{Handlers, PasswordResult, ServerBuilder};

#[tokio::test]
async fn password() {
    let mut server = ServerBuilder::default().build("[::1]:2222").await.unwrap();

    let mut handlers = Handlers::<anyhow::Error>::new();
    handlers.on_auth_password(|username, password| {
        assert_eq!(&username, "foo");
        assert_eq!(&password, "bar");
        ok(PasswordResult::Ok).boxed()
    });
    handlers.on_channel_shell(|_, _, _| ok(0).boxed());

    let task = tokio::task::spawn_blocking(|| {
        let connection = TcpStream::connect("[::1]:2222").unwrap();
        let mut session = Session::new().unwrap();
        session.set_tcp_stream(connection);
        session.handshake().unwrap();

        session.userauth_password("foo", "bar").unwrap();
        assert!(session.authenticated());
    });

    let connection = server.try_next().await.unwrap().unwrap();
    let connection = connection.accept().await.unwrap();
    connection.run(handlers).await.unwrap();

    task.await.unwrap();
}

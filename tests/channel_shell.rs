use std::ffi::CString;
use std::os::unix::io::FromRawFd;
use std::process::Stdio;

use futures::future::ok;
use futures::prelude::*;
use nix::sys::memfd::{memfd_create, MemFdCreateFlag};
use tokio::prelude::*;
use tokio::process::Command;

use ssssh::{Handlers, ServerBuilder, SshOutput};

#[tokio::test]
async fn shell() {
    simple_logger::init().ok();

    let input_name = CString::new("input").unwrap();
    let input_fd = memfd_create(&input_name, MemFdCreateFlag::empty()).unwrap();
    nix::unistd::write(input_fd, b"hello, world!").unwrap();
    nix::unistd::lseek(input_fd, 0, nix::unistd::Whence::SeekSet).unwrap();
    let input = unsafe { Stdio::from_raw_fd(input_fd) };

    let mut server = ServerBuilder::default().build("[::1]:2222").await.unwrap();

    let mut handlers = Handlers::<anyhow::Error>::new();
    handlers.on_auth_none(|_| ok(true).boxed());
    handlers.on_channel_shell(|mut stdin, mut stdout, mut stderr: SshOutput| {
        async move {
            tokio::io::copy(&mut stdin, &mut stdout).await.unwrap();
            stderr.write(b"hello, stderr!").await.unwrap();
            Ok(0)
        }
        .boxed()
    });

    let proc = Command::new("ssh")
        .env_clear()
        .arg("-oStrictHostKeyChecking=no")
        .arg("-oUserKnownHostsFile=/dev/null")
        .arg("-p2222")
        .arg("-q")
        .arg("::1")
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let connection = server.try_next().await.unwrap().unwrap();
    let connection = connection.accept().await.unwrap();
    connection.run(handlers).await.unwrap();

    let output = proc.wait_with_output().await.unwrap();
    assert!(output.status.success());
    assert_eq!(&output.stdout, b"hello, world!");
    assert_eq!(&output.stderr, b"hello, stderr!");
}

use std::ffi::CString;
use std::net::TcpStream;
use std::os::raw::{c_char, c_int, c_void};
use std::os::unix::io::AsRawFd;
use std::ptr;

use futures::future::ok;
use futures::prelude::*;
use libssh2_sys::libssh2_free;
use libssh2_sys::libssh2_session_handshake;
use libssh2_sys::libssh2_session_init_ex;
use libssh2_sys::libssh2_userauth_password_ex;
use libssh2_sys::LIBSSH2_SESSION;
use ssssh::{Handlers, PasswordResult, ServerBuilder};

#[tokio::test]
async fn password_change() {
    simple_logger::init().ok();

    let mut server = ServerBuilder::default().build("[::1]:2222").await.unwrap();

    let mut handlers = Handlers::<anyhow::Error>::new();
    handlers.on_auth_password(|_, _| ok(PasswordResult::PasswordChangeRequired("".into())).boxed());
    handlers.on_auth_change_password(|name, oldpw, newpw| {
        assert_eq!(&name, "foo");
        assert_eq!(&oldpw, "bar");
        assert_eq!(&newpw, "hoge");
        ok(PasswordResult::Ok).boxed()
    });
    handlers.on_channel_shell(|_, _, _| ok(0).boxed());

    let task = tokio::task::spawn_blocking(|| {
        let connection = TcpStream::connect("[::1]:2222").unwrap();
        let connection = connection.as_raw_fd();

        let username = CString::new("foo").unwrap();
        let password = CString::new("bar").unwrap();

        extern "C" fn password_change_cb(
            _: *mut LIBSSH2_SESSION,
            newpw: *mut *mut c_char,
            newlen: *mut c_int,
            _: *mut *mut c_void,
        ) {
            let s = CString::new("hoge").unwrap();
            unsafe {
                *newlen = s.as_bytes().len() as i32;
                *newpw = s.into_raw();
            }
        }

        unsafe {
            let session = libssh2_session_init_ex(None, None, None, ptr::null_mut());
            let r = libssh2_session_handshake(session, connection);
            assert_eq!(0, r);
            let r = libssh2_userauth_password_ex(
                session,
                username.as_ptr(),
                username.as_bytes().len() as u32,
                password.as_ptr(),
                password.as_bytes().len() as u32,
                Some(password_change_cb),
            );
            assert_eq!(0, r);
            libssh2_free(session, ptr::null_mut());
        }
    });

    let connection = server.try_next().await.unwrap().unwrap();
    let connection = connection.accept().await.unwrap();
    connection.run(handlers).await.unwrap();

    task.await.unwrap();
}

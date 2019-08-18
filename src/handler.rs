use std::fmt;
use std::error::Error as StdError;

use failure::Fail;
use futures::future::{BoxFuture, FutureExt as _};

use crate::handle::{AuthHandle, ChannelHandle};
pub use crate::msg::PtyReq;

#[derive(Debug, Fail)]
#[fail(display = "Unsupported")]
pub struct Unsupported;

pub enum Auth {
    Accept,
    Reject,
}

pub enum PasswordAuth {
    Accept,
    Reject,
    ChangePasswdreq(String),
}

pub enum PasswordChangeAuth {
    Accept,
    Partial,
    Reject,
    ChangePasswdreq(String),
}

pub trait Handler {
    type Error: Into<Box<dyn StdError + Send + Sync>> + fmt::Display + fmt::Debug + From<Unsupported>;

    fn auth_none(
        &mut self,
        _uesrname: &str,
        _auth_handle: &AuthHandle,
    ) -> BoxFuture<Result<Auth, Self::Error>> {
        async { Ok(Auth::Reject) }.boxed()
    }

    fn auth_publickey(
        &mut self,
        _username: &str,
        _publickey: &[u8],
        _handle: &AuthHandle,
    ) -> BoxFuture<Result<Auth, Self::Error>> {
        async { Ok(Auth::Reject) }.boxed()
    }

    fn auth_password(
        &mut self,
        _username: &str,
        _password: &str,
        _handle: &AuthHandle,
    ) -> BoxFuture<Result<PasswordAuth, Self::Error>> {
        async { Ok(PasswordAuth::Reject) }.boxed()
    }

    fn auth_password_change(
        &mut self,
        _username: &str,
        _oldpassword: &str,
        _newpassword: &str,
        _handle: &AuthHandle,
    ) -> BoxFuture<Result<PasswordChangeAuth, Self::Error>> {
        async { Ok(PasswordChangeAuth::Reject) }.boxed()
    }

    fn channel_open_session(
        &mut self,
        _handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        async { Ok(()) }.boxed()
    }

    fn channel_pty_request(
        &mut self,
        _pty: &PtyReq,
        _handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        async {
            Err(Unsupported.into())
        }.boxed()
    }

    fn channel_shell_request(
        &mut self,
        _handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        async {
            Err(Unsupported.into())
        }.boxed()
    }

    fn channel_exec_request(
        &mut self,
        _program: &str,
        _handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        async {
            Err(Unsupported.into())
        }.boxed()
    }

    fn channel_data(
        &mut self,
        _data: &[u8],
        _handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        async { Ok(()) }.boxed()
    }

    fn channel_eof(&mut self, _handle: &ChannelHandle) -> BoxFuture<Result<(), Self::Error>> {
        async { Ok(()) }.boxed()
    }

    fn channel_close(&mut self, _handle: &ChannelHandle) -> BoxFuture<Result<(), Self::Error>> {
        async { Ok(()) }.boxed()
    }
}

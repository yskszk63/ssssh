use std::error::Error as StdError;
use std::fmt;

use bytes::Bytes;
use failure::Fail;
use futures::future::{BoxFuture, FutureExt as _};

use crate::handle::{AuthHandle, ChannelHandle};
use crate::msg;

#[derive(Debug, Clone)]
pub struct PtyReq {
    term_name: String,
    terminal_width: u32,
    terminal_height: u32,
    terminal_width_px: u32,
    terminal_height_px: u32,
    terminal_modes: Bytes,
}

impl From<PtyReq> for msg::PtyReq {
    fn from(v: PtyReq) -> Self {
        let PtyReq {
            term_name,
            terminal_width,
            terminal_height,
            terminal_width_px,
            terminal_height_px,
            terminal_modes,
        } = v;

        Self::new(
            term_name,
            terminal_width,
            terminal_height,
            terminal_width_px,
            terminal_height_px,
            terminal_modes,
        )
    }
}

impl From<msg::PtyReq> for PtyReq {
    fn from(v: msg::PtyReq) -> Self {
        Self {
            term_name: v.term_name().into(),
            terminal_width: v.terminal_width(),
            terminal_height: v.terminal_height(),
            terminal_width_px: v.terminal_width_px(),
            terminal_height_px: v.terminal_height_px(),
            terminal_modes: v.terminal_modes().clone(),
        }
    }
}

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
    type Error: Into<Box<dyn StdError + Send + Sync>>
        + fmt::Display
        + fmt::Debug
        + From<Unsupported>;

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
        async { Err(Unsupported.into()) }.boxed()
    }

    fn channel_shell_request(
        &mut self,
        _handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        async { Err(Unsupported.into()) }.boxed()
    }

    fn channel_exec_request(
        &mut self,
        _program: &str,
        _handle: &ChannelHandle,
    ) -> BoxFuture<Result<(), Self::Error>> {
        async { Err(Unsupported.into()) }.boxed()
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

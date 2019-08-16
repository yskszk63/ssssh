use std::error::Error as StdError;
use std::fmt::{self, Display};

use futures::future::{BoxFuture, FutureExt as _};

use crate::handle::{GlobalHandle, ChannelHandle};

#[derive(Debug)]
pub struct AuthError(String);

impl Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StdError for AuthError {}

#[derive(Debug)]
pub struct ChannelError(String);

impl Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl StdError for ChannelError {}

pub enum Auth {
    Accept,
    Reject,
}

pub trait AuthHandler {
    type Error: Into<Box<dyn StdError + Send + Sync>>;

    fn handle_none(&mut self, _username: &str, _handle: GlobalHandle) -> BoxFuture<Result<Auth, Self::Error>> {
        async { Ok(Auth::Reject) }.boxed()
    }

    fn handle_publickey(
        &mut self,
        _username: &str,
        _publickey: &[u8],
        _handle: GlobalHandle,
    ) -> BoxFuture<Result<Auth, Self::Error>> {
        async { Ok(Auth::Reject) }.boxed()
    }

    fn handle_password(
        &mut self,
        _username: &str,
        _password: &[u8],
        _handle: GlobalHandle,
    ) -> BoxFuture<Result<Auth, Self::Error>> {
        async { Ok(Auth::Reject) }.boxed()
    }
}

pub trait ChannelHandler {
    type Error: Into<Box<dyn StdError + Send + Sync>>;

    fn handle_open_session(&mut self, _session_id: u32, _handle: ChannelHandle) -> BoxFuture<Result<(), Self::Error>> {
        async { Ok(()) }.boxed()
    }

    fn handle_pty_request(&mut self, _session_id: u32, _handle: ChannelHandle) -> BoxFuture<Result<(), Self::Error>> {
        async { Ok(()) }.boxed()
    }

    fn handle_shell_request(&mut self, _session_id: u32, _handle: ChannelHandle) -> BoxFuture<Result<(), Self::Error>> {
        async { Ok(()) }.boxed()
    }

    fn handle_data(&mut self, _session_id: u32, _data: &[u8], _handle: ChannelHandle) -> BoxFuture<Result<(), Self::Error>> {
        async { Ok(()) }.boxed()
    }

    fn handle_close(&mut self, _session_id: u32, _handle: ChannelHandle) -> BoxFuture<Result<(), Self::Error>> {
        async { Ok(()) }.boxed()
    }

}

//! SSH handler

use std::error::Error as StdError;
use std::ffi::OsString;

use futures::future::BoxFuture;
use futures::future::FutureExt as _;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};

pub(crate) type HandlerError = Box<dyn StdError + Send + Sync + 'static>;

/// Handler not implemented
#[derive(Debug, Error)]
#[error("not implemented")]
pub struct NotImplemented(());

/// Password authentication result
#[derive(Debug)]
pub enum PasswordResult {
    /// Ok
    Ok,

    /// Change password is required
    PasswordChangeRequired(String),

    /// Failed to authenticate password
    Failure,
}

/// SSH handler
#[async_trait::async_trait]
pub trait Handlers: Send {
    /// Error type
    type Err: Into<HandlerError> + From<NotImplemented> + Send + 'static;

    async fn handle_auth_none(&mut self, _username: &str) -> Result<bool, Self::Err> {
        Ok(false)
    }

    async fn handle_auth_password(
        &mut self,
        _username: &str,
        _password: &str,
    ) -> Result<PasswordResult, Self::Err> {
        Ok(PasswordResult::Failure)
    }

    async fn handle_auth_password_change(
        &mut self,
        _username: &str,
        _old_password: &str,
        _new_password: &str,
    ) -> Result<PasswordResult, Self::Err> {
        Ok(PasswordResult::Failure)
    }

    fn handle_channel_shell<I, O, E>(
        &mut self,
        _stdin: I,
        _stdout: O,
        _stderr: E,
    ) -> BoxFuture<'static, Result<u32, Self::Err>>
    where
        I: AsyncRead + Send + Unpin + 'static,
        O: AsyncWrite + Send + Unpin + 'static,
        E: AsyncWrite + Send + Unpin + 'static,
    {
        futures::future::err(Self::Err::from(NotImplemented(()))).boxed()
    }

    fn handle_channel_exec<I, O, E>(
        &mut self,
        _stdin: I,
        _stdout: O,
        _stderr: E,
        _prog: OsString,
    ) -> BoxFuture<'static, Result<u32, Self::Err>>
    where
        I: AsyncRead + Send + Unpin + 'static,
        O: AsyncWrite + Send + Unpin + 'static,
        E: AsyncWrite + Send + Unpin + 'static,
    {
        futures::future::err(Self::Err::from(NotImplemented(()))).boxed()
    }
}

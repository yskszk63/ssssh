//! SSH handler

use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;

use futures::future::BoxFuture;

use crate::{SshInput, SshOutput};

pub(crate) type HandlerError = Box<dyn StdError + Send + Sync + 'static>;

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

pub trait AuthNoneHandler: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(&mut self, username: String) -> BoxFuture<'static, Result<bool, Self::Error>>;
}

impl<F, E> AuthNoneHandler for F
where
    F: Fn(String) -> BoxFuture<'static, Result<bool, E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(&mut self, username: String) -> BoxFuture<'static, Result<bool, Self::Error>> {
        self(username)
    }
}

pub trait AuthPublickeyHandler: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(
        &mut self,
        username: String,
        algorithm: String,
        publickey: String,
    ) -> BoxFuture<'static, Result<bool, Self::Error>>;
}

impl<F, E> AuthPublickeyHandler for F
where
    F: Fn(String, String, String) -> BoxFuture<'static, Result<bool, E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(
        &mut self,
        username: String,
        algorithm: String,
        publickey: String,
    ) -> BoxFuture<'static, Result<bool, Self::Error>> {
        self(username, algorithm, publickey)
    }
}

pub trait AuthPasswordHandler: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(
        &mut self,
        username: String,
        password: String,
    ) -> BoxFuture<'static, Result<PasswordResult, Self::Error>>;
}

impl<F, E> AuthPasswordHandler for F
where
    F: Fn(String, String) -> BoxFuture<'static, Result<PasswordResult, E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(
        &mut self,
        username: String,
        password: String,
    ) -> BoxFuture<'static, Result<PasswordResult, Self::Error>> {
        self(username, password)
    }
}

pub trait AuthChangePasswordHandler: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(
        &mut self,
        username: String,
        oldpassword: String,
        newpassword: String,
    ) -> BoxFuture<'static, Result<PasswordResult, Self::Error>>;
}

impl<F, E> AuthChangePasswordHandler for F
where
    F: Fn(String, String, String) -> BoxFuture<'static, Result<PasswordResult, E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(
        &mut self,
        username: String,
        oldpassword: String,
        newpassword: String,
    ) -> BoxFuture<'static, Result<PasswordResult, Self::Error>> {
        self(username, oldpassword, newpassword)
    }
}

pub trait AuthHostbasedHandler: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(
        &mut self,
        username: String,
        hostname: String,
        algorithm: String,
        publickey: String,
    ) -> BoxFuture<'static, Result<bool, Self::Error>>;
}

impl<F, E> AuthHostbasedHandler for F
where
    F: Fn(String, String, String, String) -> BoxFuture<'static, Result<bool, E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(
        &mut self,
        username: String,
        hostname: String,
        algorithm: String,
        publickey: String,
    ) -> BoxFuture<'static, Result<bool, Self::Error>> {
        self(username, hostname, algorithm, publickey)
    }
}

pub trait ChannelShellHandler: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(
        &mut self,
        stdin: SshInput,
        stdout: SshOutput,
        stderr: SshOutput,
    ) -> BoxFuture<'static, Result<u32, Self::Error>>;
}

impl<F, E> ChannelShellHandler for F
where
    F: Fn(SshInput, SshOutput, SshOutput) -> BoxFuture<'static, Result<u32, E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(
        &mut self,
        stdin: SshInput,
        stdout: SshOutput,
        stderr: SshOutput,
    ) -> BoxFuture<'static, Result<u32, Self::Error>> {
        self(stdin, stdout, stderr)
    }
}

pub trait ChannelExecHandler: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(
        &mut self,
        stdin: SshInput,
        stdout: SshOutput,
        stderr: SshOutput,
        prog: OsString,
    ) -> BoxFuture<'static, Result<u32, Self::Error>>;
}

impl<F, E> ChannelExecHandler for F
where
    F: Fn(SshInput, SshOutput, SshOutput, OsString) -> BoxFuture<'static, Result<u32, E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(
        &mut self,
        stdin: SshInput,
        stdout: SshOutput,
        stderr: SshOutput,
        prog: OsString,
    ) -> BoxFuture<'static, Result<u32, Self::Error>> {
        self(stdin, stdout, stderr, prog)
    }
}

pub trait ChannelDirectTcpIpHandler: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(
        &mut self,
        ingress: SshInput,
        egress: SshOutput,
    ) -> BoxFuture<'static, Result<(), Self::Error>>;
}

impl<F, E> ChannelDirectTcpIpHandler for F
where
    F: Fn(SshInput, SshOutput) -> BoxFuture<'static, Result<(), E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(
        &mut self,
        ingress: SshInput,
        egress: SshOutput,
    ) -> BoxFuture<'static, Result<(), Self::Error>> {
        self(ingress, egress)
    }
}

#[derive(Default)]
pub struct Handlers<E>
where
    E: Into<HandlerError> + Send + 'static,
{
    auth_none: Option<Box<dyn AuthNoneHandler<Error = E>>>,
    auth_publickey: Option<Box<dyn AuthPublickeyHandler<Error = E>>>,
    auth_password: Option<Box<dyn AuthPasswordHandler<Error = E>>>,
    auth_change_password: Option<Box<dyn AuthChangePasswordHandler<Error = E>>>,
    auth_hostbased: Option<Box<dyn AuthHostbasedHandler<Error = E>>>,

    channel_shell: Option<Box<dyn ChannelShellHandler<Error = E>>>,
    channel_exec: Option<Box<dyn ChannelExecHandler<Error = E>>>,
    channel_direct_tcpip: Option<Box<dyn ChannelDirectTcpIpHandler<Error = E>>>,
}

impl<E> Handlers<E>
where
    E: Into<HandlerError> + Send + 'static,
{
    pub fn new() -> Self {
        Self {
            auth_none: None,
            auth_publickey: None,
            auth_password: None,
            auth_change_password: None,
            auth_hostbased: None,
            channel_shell: None,
            channel_exec: None,
            channel_direct_tcpip: None,
        }
    }

    pub fn on_auth_none<H>(&mut self, handler: H)
    where
        H: AuthNoneHandler<Error = E> + 'static,
    {
        self.auth_none = Some(Box::new(handler))
    }

    pub fn on_auth_publickey<H>(&mut self, handler: H)
    where
        H: AuthPublickeyHandler<Error = E> + 'static,
    {
        self.auth_publickey = Some(Box::new(handler))
    }

    pub fn on_auth_password<H>(&mut self, handler: H)
    where
        H: AuthPasswordHandler<Error = E> + 'static,
    {
        self.auth_password = Some(Box::new(handler))
    }

    pub fn on_auth_change_password<H>(&mut self, handler: H)
    where
        H: AuthChangePasswordHandler<Error = E> + 'static,
    {
        self.auth_change_password = Some(Box::new(handler))
    }

    pub fn on_auth_hostbased<H>(&mut self, handler: H)
    where
        H: AuthHostbasedHandler<Error = E> + 'static,
    {
        self.auth_hostbased = Some(Box::new(handler))
    }

    pub fn on_channel_shell<H>(&mut self, handler: H)
    where
        H: ChannelShellHandler<Error = E> + 'static,
    {
        self.channel_shell = Some(Box::new(handler))
    }

    pub fn on_channel_exec<H>(&mut self, handler: H)
    where
        H: ChannelExecHandler<Error = E> + 'static,
    {
        self.channel_exec = Some(Box::new(handler))
    }

    pub fn on_channel_direct_tcpip<H>(&mut self, handler: H)
    where
        H: ChannelDirectTcpIpHandler<Error = E> + 'static,
    {
        self.channel_direct_tcpip = Some(Box::new(handler))
    }

    pub(crate) fn dispatch_auth_none(
        &mut self,
        username: String,
    ) -> Option<BoxFuture<'static, Result<bool, E>>> {
        if let Some(handler) = &mut self.auth_none {
            Some(handler.handle(username))
        } else {
            None
        }
    }

    pub(crate) fn dispatch_auth_publickey(
        &mut self,
        username: String,
        algorithm: String,
        publickey: String,
    ) -> Option<BoxFuture<'static, Result<bool, E>>> {
        if let Some(handler) = &mut self.auth_publickey {
            Some(handler.handle(username, algorithm, publickey))
        } else {
            None
        }
    }

    pub(crate) fn dispatch_auth_password(
        &mut self,
        username: String,
        password: String,
    ) -> Option<BoxFuture<'static, Result<PasswordResult, E>>> {
        if let Some(handler) = &mut self.auth_password {
            Some(handler.handle(username, password))
        } else {
            None
        }
    }

    pub(crate) fn dispatch_auth_change_password(
        &mut self,
        username: String,
        oldpassword: String,
        newpassword: String,
    ) -> Option<BoxFuture<'static, Result<PasswordResult, E>>> {
        if let Some(handler) = &mut self.auth_change_password {
            Some(handler.handle(username, oldpassword, newpassword))
        } else {
            None
        }
    }

    pub(crate) fn dispatch_auth_hostbased(
        &mut self,
        username: String,
        hostname: String,
        algorithm: String,
        publickey: String,
    ) -> Option<BoxFuture<'static, Result<bool, E>>> {
        if let Some(handler) = &mut self.auth_hostbased {
            Some(handler.handle(username, hostname, algorithm, publickey))
        } else {
            None
        }
    }

    pub(crate) fn dispatch_channel_shell(
        &mut self,
        stdin: SshInput,
        stdout: SshOutput,
        stderr: SshOutput,
    ) -> Option<BoxFuture<'static, Result<u32, E>>> {
        if let Some(handler) = &mut self.channel_shell {
            Some(handler.handle(stdin, stdout, stderr))
        } else {
            None
        }
    }

    pub(crate) fn dispatch_channel_exec(
        &mut self,
        stdin: SshInput,
        stdout: SshOutput,
        stderr: SshOutput,
        prog: OsString,
    ) -> Option<BoxFuture<'static, Result<u32, E>>> {
        if let Some(handler) = &mut self.channel_exec {
            Some(handler.handle(stdin, stdout, stderr, prog))
        } else {
            None
        }
    }

    pub(crate) fn dispatch_direct_tcpip(
        &mut self,
        ingress: SshInput,
        egress: SshOutput,
    ) -> Option<BoxFuture<'static, Result<(), E>>> {
        if let Some(handler) = &mut self.channel_direct_tcpip {
            Some(handler.handle(ingress, egress))
        } else {
            None
        }
    }
}

impl<E> fmt::Debug for Handlers<E>
where
    E: Into<HandlerError> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handlers")
    }
}

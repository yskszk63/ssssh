//! SSH handler

use std::collections::HashMap;
use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;

use futures::future::BoxFuture;

use crate::{SshInput, SshOutput};

pub(crate) type HandlerError = Box<dyn StdError + Send + Sync + 'static>;

/// Context for SSH Session.
pub struct SessionContext<Pty = ()> {
    stdio: Option<(SshInput, SshOutput, SshOutput)>,
    env: HashMap<String, String>,
    pty: Option<Pty>,
}

impl<Pty> SessionContext<Pty> {
    pub(crate) fn new(
        stdin: SshInput,
        stdout: SshOutput,
        stderr: SshOutput,
        env: HashMap<String, String>,
        pty: Option<Pty>,
    ) -> Self {
        Self {
            stdio: Some((stdin, stdout, stderr)),
            env,
            pty,
        }
    }

    pub fn take_stdio(&mut self) -> Option<(SshInput, SshOutput, SshOutput)> {
        self.stdio.take()
    }

    pub fn env(&self) -> &HashMap<String, String> {
        &self.env
    }

    pub fn take_pty(&mut self) -> Option<Pty> {
        self.pty.take()
    }
}

/// Password authentication result.
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

pub trait ChannelRequestPtyHandler<Pty>: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(
        &mut self,
        term: String,
        width: u32,
        height: u32,
        width_px: u32,
        height_px: u32,
        modes: Vec<u8>,
    ) -> BoxFuture<'static, Result<Pty, Self::Error>>;
}

impl<F, E, Pty> ChannelRequestPtyHandler<Pty> for F
where
    F: Fn(String, u32, u32, u32, u32, Vec<u8>) -> BoxFuture<'static, Result<Pty, E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(
        &mut self,
        term: String,
        width: u32,
        height: u32,
        width_px: u32,
        height_px: u32,
        modes: Vec<u8>,
    ) -> BoxFuture<'static, Result<Pty, Self::Error>> {
        self(term, width, height, width_px, height_px, modes)
    }
}

pub trait ChannelShellHandler<Pty>: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(&mut self, ctx: SessionContext<Pty>) -> BoxFuture<'static, Result<u32, Self::Error>>;
}

impl<F, E, Pty> ChannelShellHandler<Pty> for F
where
    F: Fn(SessionContext<Pty>) -> BoxFuture<'static, Result<u32, E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(&mut self, ctx: SessionContext<Pty>) -> BoxFuture<'static, Result<u32, Self::Error>> {
        self(ctx)
    }
}

pub trait ChannelExecHandler<Pty>: Send {
    type Error: Into<HandlerError> + Send + 'static;

    fn handle(
        &mut self,
        ctx: SessionContext<Pty>,
        prog: OsString,
    ) -> BoxFuture<'static, Result<u32, Self::Error>>;
}

impl<F, E, Pty> ChannelExecHandler<Pty> for F
where
    F: Fn(SessionContext<Pty>, OsString) -> BoxFuture<'static, Result<u32, E>> + Send,
    E: Into<HandlerError> + Send + 'static,
{
    type Error = E;

    fn handle(
        &mut self,
        ctx: SessionContext<Pty>,
        prog: OsString,
    ) -> BoxFuture<'static, Result<u32, Self::Error>> {
        self(ctx, prog)
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

/// SSH callback handlers collections.
#[derive(Default)]
pub struct Handlers<E, Pty = ()>
where
    E: Into<HandlerError> + Send + 'static,
{
    auth_none: Option<Box<dyn AuthNoneHandler<Error = E>>>,
    auth_publickey: Option<Box<dyn AuthPublickeyHandler<Error = E>>>,
    auth_password: Option<Box<dyn AuthPasswordHandler<Error = E>>>,
    auth_change_password: Option<Box<dyn AuthChangePasswordHandler<Error = E>>>,
    auth_hostbased: Option<Box<dyn AuthHostbasedHandler<Error = E>>>,

    channel_pty_request: Option<Box<dyn ChannelRequestPtyHandler<Pty, Error = E>>>,
    channel_shell: Option<Box<dyn ChannelShellHandler<Pty, Error = E>>>,
    channel_exec: Option<Box<dyn ChannelExecHandler<Pty, Error = E>>>,
    channel_direct_tcpip: Option<Box<dyn ChannelDirectTcpIpHandler<Error = E>>>,
}

impl<E, Pty> Handlers<E, Pty>
where
    E: Into<HandlerError> + Send + 'static,
{
    /// Construct new Handlers instance.
    pub fn new() -> Self {
        Self {
            auth_none: None,
            auth_publickey: None,
            auth_password: None,
            auth_change_password: None,
            auth_hostbased: None,
            channel_pty_request: None,
            channel_shell: None,
            channel_exec: None,
            channel_direct_tcpip: None,
        }
    }

    /// Register None user authentication method handler.
    ///
    /// If not registered, return authentication failure.
    pub fn on_auth_none<H>(&mut self, handler: H)
    where
        H: AuthNoneHandler<Error = E> + 'static,
    {
        self.auth_none = Some(Box::new(handler))
    }

    /// Register Publickey user authentication method handler.
    ///
    /// If not registered, return authentication failure.
    pub fn on_auth_publickey<H>(&mut self, handler: H)
    where
        H: AuthPublickeyHandler<Error = E> + 'static,
    {
        self.auth_publickey = Some(Box::new(handler))
    }

    /// Register Password user authentication method handler.
    ///
    /// If not registered, return authentication failure.
    pub fn on_auth_password<H>(&mut self, handler: H)
    where
        H: AuthPasswordHandler<Error = E> + 'static,
    {
        self.auth_password = Some(Box::new(handler))
    }

    /// Register Change Password user authentication method handler.
    ///
    /// If not registered, return authentication failure.
    pub fn on_auth_change_password<H>(&mut self, handler: H)
    where
        H: AuthChangePasswordHandler<Error = E> + 'static,
    {
        self.auth_change_password = Some(Box::new(handler))
    }

    /// Register Hostbased user authentication method handler.
    ///
    /// If not registered, return authentication failure.
    pub fn on_auth_hostbased<H>(&mut self, handler: H)
    where
        H: AuthHostbasedHandler<Error = E> + 'static,
    {
        self.auth_hostbased = Some(Box::new(handler))
    }

    /// Register Request pty handler.
    ///
    /// If not registered, channel returns failure.
    pub fn on_channel_pty_request<H>(&mut self, handler: H)
    where
        H: ChannelRequestPtyHandler<Pty, Error = E> + 'static,
    {
        self.channel_pty_request = Some(Box::new(handler))
    }

    /// Register Shell channel handler.
    ///
    /// If not registered, channel returns failure.
    pub fn on_channel_shell<H>(&mut self, handler: H)
    where
        H: ChannelShellHandler<Pty, Error = E> + 'static,
    {
        self.channel_shell = Some(Box::new(handler))
    }

    /// Register Exec channel handler.
    ///
    /// If not registered, channel returns failure.
    pub fn on_channel_exec<H>(&mut self, handler: H)
    where
        H: ChannelExecHandler<Pty, Error = E> + 'static,
    {
        self.channel_exec = Some(Box::new(handler))
    }

    /// Register Direct TCP/IP channel handler.
    ///
    /// If not registered, channel returns failure.
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
        self.auth_none
            .as_mut()
            .map(|handler| handler.handle(username))
    }

    pub(crate) fn dispatch_auth_publickey(
        &mut self,
        username: String,
        algorithm: String,
        publickey: String,
    ) -> Option<BoxFuture<'static, Result<bool, E>>> {
        self.auth_publickey
            .as_mut()
            .map(|handler| handler.handle(username, algorithm, publickey))
    }

    pub(crate) fn dispatch_auth_password(
        &mut self,
        username: String,
        password: String,
    ) -> Option<BoxFuture<'static, Result<PasswordResult, E>>> {
        self.auth_password
            .as_mut()
            .map(|handler| handler.handle(username, password))
    }

    pub(crate) fn dispatch_auth_change_password(
        &mut self,
        username: String,
        oldpassword: String,
        newpassword: String,
    ) -> Option<BoxFuture<'static, Result<PasswordResult, E>>> {
        self.auth_change_password
            .as_mut()
            .map(|handler| handler.handle(username, oldpassword, newpassword))
    }

    pub(crate) fn dispatch_auth_hostbased(
        &mut self,
        username: String,
        hostname: String,
        algorithm: String,
        publickey: String,
    ) -> Option<BoxFuture<'static, Result<bool, E>>> {
        self.auth_hostbased
            .as_mut()
            .map(|handler| handler.handle(username, hostname, algorithm, publickey))
    }

    pub(crate) fn dispatch_channel_pty_req(
        &mut self,
        term: String,
        width: u32,
        height: u32,
        width_px: u32,
        height_px: u32,
        modes: Vec<u8>,
    ) -> Option<BoxFuture<'static, Result<Pty, E>>> {
        self.channel_pty_request
            .as_mut()
            .map(|handler| handler.handle(term, width, height, width_px, height_px, modes))
    }

    pub(crate) fn dispatch_channel_shell(
        &mut self,
        stdin: SshInput,
        stdout: SshOutput,
        stderr: SshOutput,
        env: HashMap<String, String>,
        pty: Option<Pty>,
    ) -> Option<BoxFuture<'static, Result<u32, E>>> {
        if let Some(handler) = &mut self.channel_shell {
            let ctx = SessionContext::new(stdin, stdout, stderr, env, pty);
            Some(handler.handle(ctx))
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
        env: HashMap<String, String>,
        pty: Option<Pty>,
    ) -> Option<BoxFuture<'static, Result<u32, E>>> {
        if let Some(handler) = &mut self.channel_exec {
            let ctx = SessionContext::new(stdin, stdout, stderr, env, pty);
            Some(handler.handle(ctx, prog))
        } else {
            None
        }
    }

    pub(crate) fn dispatch_direct_tcpip(
        &mut self,
        ingress: SshInput,
        egress: SshOutput,
    ) -> Option<BoxFuture<'static, Result<(), E>>> {
        self.channel_direct_tcpip
            .as_mut()
            .map(|handler| handler.handle(ingress, egress))
    }
}

impl<E, Pty> fmt::Debug for Handlers<E, Pty>
where
    E: Into<HandlerError> + Send + 'static,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Handlers")
    }
}

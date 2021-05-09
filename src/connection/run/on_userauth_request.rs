use futures::sink::SinkExt as _;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::userauth_failure::UserauthFailure;
use crate::msg::userauth_passwd_changereq::UserauthPasswdChangereq;
use crate::msg::userauth_pk_ok::UserauthPkOk;
use crate::msg::userauth_request::{Hostbased, Method, Password, Publickey, UserauthRequest};
use crate::msg::userauth_success::UserauthSuccess;
use crate::msg::UserauthPkMsg;
use crate::pack::Pack;
use crate::{HandlerError, PasswordResult};
use bytes::Bytes;
use log::debug;

use super::{Runner, SshError};

const SUPPORTED_METHODS: &[&str] = &["publickey", "password", "hostbased"];

#[derive(Debug)]
pub(super) struct AuthState {
    remaining: Vec<&'static str>,
}

impl AuthState {
    pub(super) fn new() -> Self {
        Self {
            remaining: Vec::from(SUPPORTED_METHODS),
        }
    }

    fn consume(&mut self, method: &str) {
        self.remaining.retain(|m| *m != method);
    }

    fn remaining(&self) -> &[&'static str] {
        &self.remaining
    }

    fn done(&mut self) {
        self.remaining.clear();
    }
}

impl<IO, E, Pty> Runner<IO, E, Pty>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) async fn on_userauth_request(
        &mut self,
        userauth_request: &UserauthRequest,
    ) -> Result<(), SshError> {
        let user_name = userauth_request.user_name();
        match userauth_request.method() {
            Method::None => self.on_userauth_none(user_name).await,

            Method::Publickey(item) if item.signature().is_none() => {
                self.on_userauth_publickey_nosig(user_name, item).await
            }

            Method::Publickey(item) if item.signature().is_some() => {
                self.on_userauth_publickey_sig(userauth_request, user_name, item)
                    .await
            }

            Method::Password(item) if item.newpassword().is_none() => {
                self.on_userauth_password(user_name, item).await
            }

            Method::Password(item) => self.on_userauth_password_change(user_name, item).await,

            Method::Hostbased(item) => {
                self.on_userauth_hostbased(userauth_request, user_name, item)
                    .await
            }

            x => {
                debug!("unknown auth method {:?}", x);
                self.send_failure(None).await
            }
        }
    }

    async fn send_success(&mut self) -> Result<(), SshError> {
        self.auth_state.done();
        self.send(UserauthSuccess::new()).await?;
        Ok(())
    }

    async fn send_failure(&mut self, consume: Option<&'static str>) -> Result<(), SshError> {
        if let Some(consume) = consume {
            self.auth_state.consume(consume);
        }
        let methods = self.auth_state.remaining();
        let msg = UserauthFailure::new(methods.iter().cloned().collect(), false);
        self.send(msg).await?;
        Ok(())
    }

    async fn on_userauth_none(&mut self, user_name: &str) -> Result<(), SshError> {
        let user_name = user_name.into();

        let r = if let Some(fut) = self.handlers.dispatch_auth_none(user_name) {
            fut.await.map_err(|e| SshError::HandlerError(e.into()))?
        } else {
            false
        };

        if r {
            self.send_success().await
        } else {
            self.send_failure(None).await
        }
    }

    async fn on_userauth_publickey_nosig(
        &mut self,
        user_name: &str,
        item: &Publickey,
    ) -> Result<(), SshError> {
        let username = user_name.into();
        let algorithm = item.algorithm().into();
        let publickey = item.blob().to_string();

        let r = if let Some(fut) = self
            .handlers
            .dispatch_auth_publickey(username, algorithm, publickey)
        {
            fut.await.map_err(|e| SshError::HandlerError(e.into()))?
        } else {
            false
        };

        if r {
            let m = UserauthPkOk::new(item.algorithm().into(), item.blob().clone()).into();
            self.io.context::<UserauthPkMsg>().send(m).await?;
        } else {
            self.send_failure(Some("publickey")).await?;
        };
        Ok(())
    }

    async fn on_userauth_publickey_sig(
        &mut self,
        userauth_request: &UserauthRequest,
        user_name: &str,
        item: &Publickey,
    ) -> Result<(), SshError> {
        let signature = item.signature().as_ref().unwrap().clone();

        let pubkey = item.blob().clone();
        let mut verifier = pubkey.verifier()?;

        self.io
            .get_ref()
            .state()
            .session_id()
            .iter()
            .cloned()
            .collect::<Bytes>()
            .pack(&mut verifier);
        50u8.pack(&mut verifier);
        user_name.pack(&mut verifier);
        userauth_request.service_name().pack(&mut verifier);
        "publickey".pack(&mut verifier);
        true.pack(&mut verifier);
        item.algorithm().to_string().pack(&mut verifier);
        item.blob().pack(&mut verifier);

        if verifier.verify(&signature) {
            let username = user_name.into();
            let algorithm = item.algorithm().into();
            let publickey = item.blob().to_string();

            let r = if let Some(fut) = self
                .handlers
                .dispatch_auth_publickey(username, algorithm, publickey)
            {
                fut.await.map_err(|e| SshError::HandlerError(e.into()))?
            } else {
                false
            };

            if r {
                self.send_success().await
            } else {
                self.send_failure(Some("publickey")).await
            }
        } else {
            self.send_failure(Some("publickey")).await
        }
    }

    async fn on_userauth_password(
        &mut self,
        user_name: &str,
        item: &Password,
    ) -> Result<(), SshError> {
        let username = user_name.into();
        let password = item.password().into();

        let r = if let Some(fut) = self.handlers.dispatch_auth_password(username, password) {
            fut.await.map_err(|e| SshError::HandlerError(e.into()))?
        } else {
            PasswordResult::Failure
        };

        match r {
            PasswordResult::Ok => self.send_success().await,
            PasswordResult::PasswordChangeRequired(message) => {
                let m = UserauthPasswdChangereq::new(message, "".into());
                self.send(m).await
            }
            PasswordResult::Failure => self.send_failure(Some("password")).await,
        }
    }

    async fn on_userauth_password_change(
        &mut self,
        user_name: &str,
        item: &Password,
    ) -> Result<(), SshError> {
        let username = user_name.into();
        let oldpassword = item.password().into();
        let newpassword = item.newpassword().clone().unwrap();

        let r = if let Some(fut) =
            self.handlers
                .dispatch_auth_change_password(username, oldpassword, newpassword)
        {
            fut.await.map_err(|e| SshError::HandlerError(e.into()))?
        } else {
            PasswordResult::Failure
        };

        match r {
            PasswordResult::Ok => self.send_success().await,
            PasswordResult::PasswordChangeRequired(message) => {
                let m = UserauthPasswdChangereq::new(message, "".into());
                self.send(m).await
            }
            PasswordResult::Failure => self.send_failure(Some("password")).await,
        }
    }

    async fn on_userauth_hostbased(
        &mut self,
        userauth_request: &UserauthRequest,
        user_name: &str,
        item: &Hostbased,
    ) -> Result<(), SshError> {
        let signature = item.signature().clone();

        let pubkey = item.client_hostkey().clone();
        let mut verifier = pubkey.verifier()?;

        self.io
            .get_ref()
            .state()
            .session_id()
            .iter()
            .cloned()
            .collect::<Bytes>()
            .pack(&mut verifier);
        50u8.pack(&mut verifier);
        user_name.pack(&mut verifier);
        userauth_request.service_name().pack(&mut verifier);
        "hostbased".pack(&mut verifier);
        item.algorithm().to_string().pack(&mut verifier);
        item.client_hostkey().pack(&mut verifier);
        item.client_hostname().pack(&mut verifier);
        item.user_name().pack(&mut verifier);

        if verifier.verify(&signature) {
            let username = user_name.into();
            let hostname = item.client_hostname().into();
            let algorithm = item.algorithm().into();
            let publickey = item.client_hostkey().to_string();

            let r = if let Some(fut) = self
                .handlers
                .dispatch_auth_hostbased(username, hostname, algorithm, publickey)
            {
                fut.await.map_err(|e| SshError::HandlerError(e.into()))?
            } else {
                false
            };

            if r {
                self.send_success().await
            } else {
                self.send_failure(Some("hostbased")).await
            }
        } else {
            self.send_failure(Some("hostbased")).await
        }
    }
}

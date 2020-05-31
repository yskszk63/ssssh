use futures::sink::SinkExt as _;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::msg::userauth_failure::UserauthFailure;
use crate::msg::userauth_passwd_changereq::UserauthPasswdChangereq;
use crate::msg::userauth_pk_ok::UserauthPkOk;
use crate::msg::userauth_request::{Hostbased, Method, Password, Publickey, UserauthRequest};
use crate::msg::userauth_success::UserauthSuccess;
use crate::msg::UserauthPkMsg;
use crate::pack::Pack;
use crate::{Handlers, PasswordResult};
use bytes::Buf as _;
use log::debug;

use super::{Runner, SshError};

impl<IO, H> Runner<IO, H>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    H: Handlers,
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
                self.send_failure(&[]).await
            }
        }
    }

    async fn send_success(&mut self) -> Result<(), SshError> {
        self.send(UserauthSuccess::new()).await?;
        Ok(())
    }

    async fn send_failure(&mut self, methods: &[&str]) -> Result<(), SshError> {
        let msg = UserauthFailure::new(methods.into_iter().cloned().collect(), false);
        self.send(msg).await?;
        Ok(())
    }

    async fn on_userauth_none(&mut self, user_name: &str) -> Result<(), SshError> {
        let r = self
            .handlers
            .handle_auth_none(user_name)
            .await
            .map_err(|e| SshError::HandlerError(e.into()))?;

        if r {
            self.send_success().await
        } else {
            self.send_failure(&["publickey", "password", "hostbased"])
                .await
        }
    }

    async fn on_userauth_publickey_nosig(
        &mut self,
        user_name: &str,
        item: &Publickey,
    ) -> Result<(), SshError> {
        let blob = item.blob().to_string();
        let r = self
            .handlers
            .handle_auth_publickey(user_name, item.algorithm(), &blob)
            .await
            .map_err(|e| SshError::HandlerError(e.into()))?;

        if r {
            let m = UserauthPkOk::new(item.algorithm().into(), item.blob().clone()).into();
            self.io.context::<UserauthPkMsg>().send(m).await?;
        } else {
            self.send_failure(&["password", "hostbased"]).await?;
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
            .to_bytes()
            .pack(&mut verifier);
        50u8.pack(&mut verifier);
        user_name.pack(&mut verifier);
        userauth_request.service_name().pack(&mut verifier);
        "publickey".pack(&mut verifier);
        true.pack(&mut verifier);
        item.algorithm().to_string().pack(&mut verifier);
        item.blob().pack(&mut verifier);

        // TODO check acceptable

        if verifier.verify(&signature) {
            self.send_success().await
        } else {
            self.send_failure(&["password", "hostbased"]).await
        }
    }

    async fn on_userauth_password(
        &mut self,
        user_name: &str,
        item: &Password,
    ) -> Result<(), SshError> {
        let r = self
            .handlers
            .handle_auth_password(user_name, item.password())
            .await
            .map_err(|e| SshError::HandlerError(e.into()))?;

        match r {
            PasswordResult::Ok => self.send_success().await,
            PasswordResult::PasswordChangeRequired(message) => {
                let m = UserauthPasswdChangereq::new(message, "".into());
                self.send(m).await
            }
            PasswordResult::Failure => self.send_failure(&["hostbased"]).await,
        }
    }

    async fn on_userauth_password_change(
        &mut self,
        user_name: &str,
        item: &Password,
    ) -> Result<(), SshError> {
        let newpassword = item.newpassword().as_ref().unwrap();
        let r = self
            .handlers
            .handle_auth_password_change(user_name, item.password(), newpassword)
            .await
            .map_err(|e| SshError::HandlerError(e.into()))?;

        match r {
            PasswordResult::Ok => self.send_success().await,
            PasswordResult::PasswordChangeRequired(message) => {
                let m = UserauthPasswdChangereq::new(message, "".into());
                self.send(m).await
            }
            PasswordResult::Failure => self.send_failure(&["hostbased"]).await,
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
            .to_bytes()
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
            let blob = item.client_hostkey().to_string();
            let r = self
                .handlers
                .handle_auth_hostbased(user_name, item.algorithm(), item.client_hostname(), &blob)
                .await
                .map_err(|e| SshError::HandlerError(e.into()))?;

            if r {
                self.send_success().await
            } else {
                self.send_failure(&[]).await
            }
        } else {
            self.send_failure(&[]).await
        }
    }
}

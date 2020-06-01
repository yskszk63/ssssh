use futures::stream::TryStreamExt as _;
use log::debug;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::kex::Kex;
use crate::msg::kexinit::Kexinit;
use crate::msg::new_keys::NewKeys;
use crate::msg::Msg;
use crate::negotiate::negotiate;
use crate::HandlerError;

use super::{Runner, SshError};

impl<IO, E> Runner<IO, E>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send,
    E: Into<HandlerError> + Send + 'static,
{
    pub(super) async fn on_kexinit(&mut self, kexinit: &Kexinit) -> Result<(), SshError> {
        let c_kexinit = kexinit;
        let s_kexinit = if self.first_kexinit.is_some() {
            self.first_kexinit.take().unwrap()
        } else {
            let s_kexinit = self.preference.to_kexinit();
            self.send(s_kexinit.clone()).await?;
            s_kexinit
        };

        let algorithm = negotiate(&c_kexinit, &s_kexinit)?;
        debug!("algorithm: {:?}", algorithm);

        let hostkey = self
            .preference
            .hostkeys()
            .lookup(algorithm.server_host_key_algorithm())
            .unwrap();
        let kex = Kex::new(algorithm.kex_algorithm())?;

        debug!("Begin kex.. {:?}", kex);
        let (hash, key) = kex
            .kex(
                &mut self.io,
                &self.c_version,
                &self.s_version,
                &c_kexinit,
                &s_kexinit,
                hostkey,
            )
            .await?;
        debug!("Done kex. {:?}", kex);

        match self.io.try_next().await? {
            Some(Msg::NewKeys(..)) => {}
            Some(msg) => return Err(SshError::UnexpectedMsg(format!("{:?}", msg))),
            None => return Err(SshError::NoPacketReceived),
        };
        self.send(NewKeys::new()).await?;

        let state = self.io.get_mut().state_mut();
        state.change_key(&hash, &key, &kex, &algorithm)?;
        Ok(())
    }
}

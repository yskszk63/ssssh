#![warn(clippy::pedantic)]

pub use connection::{Connection, Error};
pub use handle::{AuthHandle, ChannelHandle, SendError, SendResult};
pub use handler::{Auth, Handler, PasswordAuth, PasswordChangeAuth, Unsupported, PtyReq};
pub use server::{AcceptError, Server, ServerBuilder};

mod algorithm;
mod compression;
mod connection;
mod encrypt;
mod handle;
mod handler;
mod hostkey;
mod kex;
mod mac;
mod msg;
mod named;
mod server;
mod sshbuf;
mod transport;
mod util;

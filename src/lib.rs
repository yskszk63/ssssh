#![feature(async_await)]
#![warn(clippy::pedantic)]

pub use handle::{AuthHandle, ChannelHandle};
pub use handler::{Auth, Handler, Unsupported};
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

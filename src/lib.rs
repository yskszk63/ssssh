//! `ssssh` is a server-sice Rust library for implementing the SSH2 protocol.
//!
//! # Example
//! ```rust
//! # use std::process::Stdio;
//! # use tokio::process::Command;
//! use futures::prelude::*;
//! use futures::future::ok;
//! use ssssh::{Handlers, ServerBuilder};
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let mut server = ServerBuilder::default()
//!         .build("[::1]:2222") // Listen port 2222
//!         .await?;
//!
//!     let mut handlers = Handlers::<anyhow::Error>::new();
//!     handlers.on_auth_none(|_| ok(true).boxed()); // Allow anonymous auth method.
//!     handlers.on_channel_shell(|_| ok(0).boxed()); // Shell channel return 0 immediately.
//!
//!     // ...Connecting to 2222 port from ssh program.
//!     # let proc = Command::new("ssh")
//!     #   .env_clear()
//!     #   .arg("-oStrictHostKeyChecking=no")
//!     #   .arg("-oUserKnownHostsFile=/dev/null")
//!     #   .arg("-p2222")
//!     #   .arg("::1")
//!     #   .stdin(Stdio::null())
//!     #   .stdout(Stdio::null())
//!     #   .stderr(Stdio::null())
//!     #   .spawn()
//!     #   .unwrap();
//!
//!     let connection = server.try_next().await?.unwrap();
//!     let connection = connection.accept().await?; // Handshake
//!     connection.run(handlers).await?; // Run with handlers
//!
//!     # proc.wait_with_output().await.unwrap();
//!     Ok(())
//! }
//! ```

pub use cipher::Algorithm as Cipher;
pub use comp::Algorithm as Compression;
pub use connection::{Connection, SshInput, SshOutput};
pub use error::SshError;
pub use handlers::*;
pub use kex::Algorithm as Kex;
pub use key::{Algorithm as Key, PublicKey};
pub use mac::Algorithm as Mac;
pub use server::{Builder as ServerBuilder, Server};

mod cipher;
mod comp;
mod connection;
mod error;
mod handlers;
mod hash;
mod hostkey;
mod kex;
mod key;
mod mac;
mod msg;
mod negotiate;
mod pack;
mod preference;
mod server;
mod state;
mod stream;

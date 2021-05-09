use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::process::Stdio;

use futures::future::ok;
use futures::future::{FutureExt as _, TryFutureExt as _};
use futures::stream::TryStreamExt as _;
use nix::fcntl::{fcntl, FcntlArg, OFlag};
use nix::pty::{grantpt, posix_openpt, ptsname, unlockpt, PtyMaster, Winsize};
use nix::unistd::{close, dup, setsid};
use tokio::fs::{File, OpenOptions};
use tokio::io;
use tokio::process::Command;
use tokio_pipe::{PipeRead, PipeWrite};

use ssssh::Handlers;
use ssssh::ServerBuilder;

nix::ioctl_write_ptr_bad!(tiocswinsz, nix::libc::TIOCSWINSZ, Winsize);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut server = ServerBuilder::default().build("[::1]:2222").await?;
    while let Some(conn) = server.try_next().await? {
        tokio::spawn(
            async move {
                let conn = conn.accept().await?;
                let mut handlers = Handlers::<anyhow::Error, (PtyMaster, File)>::new();

                handlers.on_auth_none(|_| ok(true).boxed());
                handlers.on_channel_pty_request(|_, width, height, _, _, _| {
                    async move {
                        let master = posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY)?;
                        grantpt(&master)?;
                        unlockpt(&master)?;

                        let flag = fcntl(master.as_raw_fd(), FcntlArg::F_GETFL)?;
                        let flag = OFlag::from_bits_truncate(flag);
                        if !flag.contains(OFlag::O_NONBLOCK) || !flag.contains(OFlag::O_CLOEXEC) {
                            fcntl(
                                master.as_raw_fd(),
                                FcntlArg::F_SETFL(flag | OFlag::O_NONBLOCK),
                            )?;
                        }

                        let winsize = Winsize {
                            ws_col: width as u16,
                            ws_row: height as u16,
                            ws_xpixel: 0,
                            ws_ypixel: 0,
                        };
                        unsafe {
                            tiocswinsz(master.as_raw_fd(), (&winsize) as *const _)?;
                        }
                        // TODO set termios

                        let slavename = unsafe { ptsname(&master)? };
                        let slave = OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&slavename)
                            .await?;
                        Ok((master, slave))
                    }
                    .boxed()
                });
                handlers.on_channel_shell(|mut ctx: ssssh::SessionContext<(PtyMaster, File)>| {
                    let (mut stdin, mut stdout, stderr) = ctx.take_stdio().unwrap();
                    let pty = ctx.take_pty();
                    async move {
                        if let Some((master, slave)) = pty {
                            let ptyin = slave.try_clone().await?.into_std().await.into_raw_fd();
                            let ptyout = slave.try_clone().await?.into_std().await.into_raw_fd();
                            let ptyerr = slave.try_clone().await?.into_std().await.into_raw_fd();
                            drop(slave);

                            let mut builder = Command::new("bash");
                            builder
                                .stdin(unsafe { Stdio::from_raw_fd(ptyin) })
                                .stdout(unsafe { Stdio::from_raw_fd(ptyout) })
                                .stderr(unsafe { Stdio::from_raw_fd(ptyerr) });
                            let master_fd = master.into_raw_fd();
                            unsafe {
                                builder.pre_exec(move || {
                                    close(master_fd)
                                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                                    setsid()
                                        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
                                    Ok(())
                                });
                            }
                            let mut child = builder.spawn()?;
                            drop(ptyin);
                            drop(ptyout);
                            drop(ptyerr);

                            let mut ptyout = unsafe { PipeRead::from_raw_fd(dup(master_fd)?) };
                            let mut ptyin = unsafe { PipeWrite::from_raw_fd(master_fd) };
                            tokio::spawn(async move {
                                let r = io::copy(&mut stdin, &mut ptyin).await;
                                println!("### END1 {:?}", r);
                            });
                            tokio::spawn(async move {
                                let r = io::copy(&mut ptyout, &mut stdout).await;
                                println!("### END2 {:?}", r); // May be IO Error at EOF.
                            });
                            let status = child.wait().await?;

                            return Ok(status.code().unwrap_or(255) as u32);
                        }

                        let stdin = unsafe { Stdio::from_raw_fd(stdin.into_raw_fd()) };
                        let stdout = unsafe { Stdio::from_raw_fd(stdout.into_raw_fd()) };
                        let stderr = unsafe { Stdio::from_raw_fd(stderr.into_raw_fd()) };
                        let status = Command::new("bash")
                            .stdin(stdin)
                            .stdout(stdout)
                            .stderr(stderr)
                            .status()
                            .await?;
                        Ok(status.code().unwrap_or(255) as u32)
                    }
                    .boxed()
                });
                conn.run(handlers).await?;
                Ok::<_, anyhow::Error>(())
            }
            .map_err(|e| println!("{}", e)),
        );
    }

    Ok(())
}

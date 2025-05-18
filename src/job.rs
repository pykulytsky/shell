use nix::unistd::dup;
use std::ffi::OsStr;
use std::os::fd::OwnedFd;
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::task::JoinHandle;

use tokio::fs::File;
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub struct Job {
    name: String,
    process: Child,
    pid: Option<u32>,
    // Cancellation token used to cancel stdin and stdout tasks.
    cancel_token: Arc<CancellationToken>,
    master_writer: File,
    master_reader: File,
    /// Wheater shell itself is interactive
    is_interactive: Arc<AtomicBool>,
}

impl Job {
    pub async fn new(
        name: impl AsRef<OsStr>,
        slave: &OwnedFd,
        master: impl AsRef<File>,
        is_interactive: impl AsRef<Arc<AtomicBool>>,
        cancel_token: impl AsRef<Arc<CancellationToken>>,
    ) -> io::Result<Self> {
        let name = name
            .as_ref()
            .to_str()
            .expect("utf-8 validation happens on higher level")
            .to_string();

        let slave_stdin = std::fs::File::from(dup(slave)?);
        let slave_stdout = std::fs::File::from(dup(slave)?);
        let slave_stderr = std::fs::File::from(dup(slave)?);

        let child = Command::new(&name)
            .stdin(Stdio::from(slave_stdin))
            .stdout(Stdio::from(slave_stdout))
            .stderr(Stdio::from(slave_stderr))
            .spawn()?;

        let pid = child.id();

        let master_writer = master.as_ref().try_clone().await?;
        let master_reader = master.as_ref().try_clone().await?;

        Ok(Self {
            name,
            process: child,
            pid,
            cancel_token: Arc::clone(cancel_token.as_ref()),
            master_writer,
            master_reader,
            is_interactive: Arc::clone(is_interactive.as_ref()),
        })
    }

    // TODO: stderr
    pub async fn spawn(&mut self) -> io::Result<(JoinHandle<()>, JoinHandle<()>)> {
        let stdin_is_interactive = self.is_interactive.clone();
        let stdin_cancel_token = self.cancel_token.clone();
        let mut master_writer = self.master_writer.try_clone().await?;
        let stdin_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            loop {
                if !stdin_is_interactive.load(Ordering::Acquire) {
                    let mut stdin = tokio::io::stdin();
                    let read_result = stdin_cancel_token
                        .run_until_cancelled(stdin.read(&mut buf))
                        .await;

                    match read_result {
                        Some(Ok(n)) => {
                            if n == 0 {
                                break;
                            }
                            if master_writer.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        _ => {
                            break;
                        }
                    }

                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        });

        let stdout_is_interactive = self.is_interactive.clone();
        let stdout_cancel_token = self.cancel_token.clone();
        let mut master_reader = self.master_reader.try_clone().await?;
        let stdout_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let mut stdout = io::stdout();
            loop {
                if !stdout_is_interactive.load(Ordering::Acquire) {
                    let read_result = stdout_cancel_token
                        .run_until_cancelled(master_reader.read(&mut buf))
                        .await;
                    let n = match read_result {
                        None | Some(Ok(0)) | Some(Err(_)) => {
                            break;
                        }
                        Some(Ok(n)) => n,
                    };
                    stdout.write_all(&buf[..n]).await.unwrap();
                    stdout.flush().await.unwrap();
                }
            }
        });

        Ok((stdin_task, stdout_task))
    }

    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        let exit_status = self.process.wait().await?;
        self.is_interactive.store(true, Ordering::Release);
        self.cancel_token.cancel();
        Ok(exit_status)
    }
}

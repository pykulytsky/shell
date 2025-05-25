use nix::unistd::dup;
use std::io::Read;
use std::io::Write;
use std::ops::{Deref, DerefMut};
use std::os::fd::OwnedFd;
use std::process::{ExitStatus, Stdio};
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::LazyLock;
use tokio::io::{self, AsyncReadExt};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use tokio::fs::File;
use tokio::process::{Child, Command};
use tokio_util::sync::CancellationToken;

use crate::command::ExternalCommand;
use crate::tty::drain_pty;
use crate::utils::set_stdin_blocking;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum JobState {
    Started,
    Running,
    Stopped,
}

static ID: LazyLock<AtomicUsize> = LazyLock::new(|| AtomicUsize::new(1));

pub type JobId = usize;

#[derive(Debug)]
pub struct Master(File);

impl Master {
    pub async fn try_clone(&self) -> io::Result<Self> {
        Ok(Self(self.0.try_clone().await?))
    }
}

impl Deref for Master {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Master {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug)]
pub struct JobHandle<R = ()> {
    pub stdout: JoinHandle<R>,
    pub stdin: JoinHandle<R>,
}

impl<R> JobHandle<R> {
    pub fn new(stdin: JoinHandle<R>, stdout: JoinHandle<R>) -> Self {
        Self { stdout, stdin }
    }

    pub async fn wait(self) -> io::Result<()> {
        self.stdin.await?;
        self.stdout.await?;

        Ok(())
    }
}

#[derive(Debug)]
pub struct Job {
    pub id: JobId,
    pub name: String,
    pub process: Child,
    pub pid: Option<u32>,
    // Cancellation token used to cancel stdin and stdout tasks.
    cancel_token: CancellationToken,
    master_writer: Master,
    master_reader: Master,
    /// Wheater shell itself is interactive
    is_interactive: Arc<AtomicBool>,
    pub(crate) stopped: Arc<AtomicBool>,
    pub(crate) state: JobState,
    is_in_bg: Arc<AtomicBool>,
}

impl Job {
    /// Constructs new pty (Pseudo-terminal) and spawns a child in this pty.
    pub async fn new(
        command: ExternalCommand,
        slave: &OwnedFd,
        master: &File,
        is_interactive: &Arc<AtomicBool>,
    ) -> io::Result<Self> {
        let name = command
            .name
            .to_str()
            .expect("utf-8 validation happens on higher level")
            .to_string();

        let slave_stdin = std::fs::File::from(dup(slave)?);
        let slave_stdout = std::fs::File::from(dup(slave)?);
        let slave_stderr = std::fs::File::from(dup(slave)?);

        let child = Command::new(&command.name)
            .args(command.args)
            .stdin(Stdio::from(slave_stdin))
            .stdout(Stdio::from(slave_stdout))
            .stderr(Stdio::from(slave_stderr))
            .spawn()?;

        let pid = child.id();

        let master_writer = Master(master.try_clone().await?);
        let master_reader = Master(master.try_clone().await?);

        let id = ID.fetch_add(1, Ordering::Relaxed);

        Ok(Self {
            id,
            name,
            process: child,
            pid,
            cancel_token: CancellationToken::new(),
            master_writer,
            master_reader,
            is_interactive: Arc::clone(is_interactive),
            stopped: Arc::new(AtomicBool::new(false)),
            state: JobState::Started,
            is_in_bg: Arc::new(AtomicBool::new(command.is_bg_job)),
        })
    }

    /// Constructs dedicated [`JoinHandle`] for stdin and stdout of a inner process,
    /// that will read/write from and to master pty.
    // TODO: stderr
    pub async fn spawn(&mut self) -> io::Result<JobHandle<()>> {
        let stdin_is_interactive = self.is_interactive.clone();
        let stdin_stopped = self.stopped.clone();
        let stdin_cancel_token = self.cancel_token.clone();
        let is_in_bg = self.is_in_bg.clone();
        let master_writer = self.master_writer.try_clone().await?;
        let Master(writer) = master_writer;
        let mut master_writer = writer.try_into_std().unwrap();
        let stdin_task = tokio::task::spawn_blocking(move || {
            let mut stdin = std::io::stdin();
            // Set stdin to non-blocking mode
            nix::fcntl::fcntl(
                &stdin,
                nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
            )
            .unwrap();
            let mut buf = [0u8; 1024];

            while !stdin_cancel_token.is_cancelled() {
                if !stdin_is_interactive.load(Ordering::SeqCst)
                    && !stdin_stopped.load(Ordering::SeqCst)
                    && !is_in_bg.load(Ordering::SeqCst)
                {
                    match stdin.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if master_writer.write_all(&buf[..n]).is_err() {
                                break;
                            }
                            while master_writer.flush().is_err() {}
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(20));
                        }
                        Err(_) => break,
                    }
                } else {
                    std::thread::yield_now();
                }
            }
            set_stdin_blocking().unwrap();
        });

        let stdout_is_interactive = self.is_interactive.clone();
        let stdout_stopped = self.stopped.clone();
        let stdout_cancel_token = self.cancel_token.clone();
        let mut master_reader = self.master_reader.try_clone().await?;

        let is_in_bg = self.is_in_bg.clone();
        let stdout_task = tokio::spawn(async move {
            let mut stdout = std::io::stdout();
            let mut buf = [0u8; 1024];

            loop {
                if (!stdout_is_interactive.load(Ordering::SeqCst)
                    && !stdout_stopped.load(Ordering::SeqCst))
                    || is_in_bg.load(Ordering::SeqCst)
                {
                    tokio::select! {
                        _ = stdout_cancel_token.cancelled() => break,
                        read_result = master_reader.read(&mut buf) => {
                            let n = match read_result {
                                Ok(n) => {
                                    if n == 0 {
                                        break;
                                    }
                                    n
                                },
                                Err(_) => break,
                            };
                            while stdout.write_all(&buf[..n]).is_err() {};
                            while stdout.flush().is_err() {};
                        }

                    }
                }
            }
        });

        self.state = JobState::Running;

        Ok(JobHandle::new(stdin_task, stdout_task))
    }

    /// Waits for the inner process to complete, terminating all associated spawned tasks.
    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        let exit_status = self.process.wait().await?;
        drain_pty(&*self.master_reader);
        drain_pty(&*self.master_writer);
        self.cancel_token.cancel();

        Ok(exit_status)
    }

    pub fn stop(&mut self) {
        self.state = JobState::Stopped;
        self.stopped.store(true, Ordering::SeqCst);
    }

    pub fn resume(&mut self) {
        self.state = JobState::Running;
        self.stopped.store(false, Ordering::SeqCst);
    }
}

#[derive(Debug)]
pub struct BgJob {
    pub(crate) job: Arc<Mutex<Job>>,
    pub(crate) handle: JobHandle,
    pub finished: tokio::sync::mpsc::UnboundedSender<(JobId, ExitStatus)>,
}

impl BgJob {
    pub fn new(
        job: Job,
        handle: JobHandle,
        finished: &tokio::sync::mpsc::UnboundedSender<(JobId, ExitStatus)>,
    ) -> Self {
        let state = job.state;
        let job = Arc::new(Mutex::new(job));
        if state == JobState::Running {
            let wait_job = job.clone();
            let wait_finished = finished.clone();
            tokio::spawn(async move {
                loop {
                    // TODO: send status code
                    let exited = wait_job.lock().await.process.try_wait();
                    if let Ok(Some(exit_status)) = exited {
                        wait_finished
                            .send((wait_job.lock().await.id, exit_status))
                            .unwrap();
                        break;
                    } else {
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            });
        }
        Self {
            job,
            handle,
            finished: finished.clone(),
        }
    }
}

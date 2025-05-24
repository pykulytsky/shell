#![allow(clippy::nonminimal_bool)]

use crate::utils::*;
use autocomplete::Trie;
use command::{Builtin, Command, CommandKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use job::{BgJob, Job, JobHandle, JobState};
use nix::pty::{openpty, OpenptyResult, Winsize};
use prompt::DirPrompt;
use readline::constants::{BUILTINS, DOUBLE_QUOTES_ESCAPE};
use readline::signal::Signal;
use readline::Readline;
use std::ffi::OsString;
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::fs::PermissionsExt;
use std::process::{exit, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::io::{stderr, stdout, AsyncWrite};
use tokio::select;
use tokio::signal::unix::SignalKind;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::{
    fs::{read_dir, DirEntry},
    io::{self, AsyncWriteExt},
};
use tokio_util::sync::CancellationToken;

pub mod autocomplete;
pub mod command;
pub mod job;
pub mod prompt;
pub mod readline;
mod tokenizer;
pub mod tty;
mod utils;

#[derive(Debug)]
pub struct Shell {
    pub path: String,
    path_executables: Vec<DirEntry>,
    last_status: Option<ExitStatus>,
    pub autocomplete_options: Trie,

    fg_job_pid: Arc<Mutex<Option<u32>>>,
    bg_jobs: std::collections::BTreeMap<usize, BgJob>,

    is_interactive: Arc<AtomicBool>,
    notify_is_interactive: Arc<Notify>,
    sigtstp_received: Arc<Notify>,

    readline_rx: UnboundedReceiver<(String, Signal)>, // maybe should use watch channel
    readline_tx: UnboundedSender<(String, Signal)>,

    cancellation_token: CancellationToken,
}

impl Shell {
    pub async fn new() -> io::Result<Self> {
        let path = std::env::var("PATH").unwrap_or_else(|_| "".to_string());
        set_shell_envs();
        let path_executables = populate_path_executables(&path).await;

        let mut autocomplete_options = Trie::new();
        autocomplete_options.extend(BUILTINS);
        for path in &path_executables {
            if let Some(p) = path.file_name().to_str() {
                autocomplete_options.insert(p);
            }
        }

        let (command_tx, command_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancellation_token = CancellationToken::new();
        let notify_is_interactive = Arc::new(tokio::sync::Notify::new());
        let sigtstp_received = Arc::new(tokio::sync::Notify::new());
        let bg_jobs = std::collections::BTreeMap::new();

        Ok(Self {
            path,
            path_executables,
            last_status: None,
            autocomplete_options,
            readline_tx: command_tx,
            readline_rx: command_rx,
            cancellation_token,
            is_interactive: Arc::new(AtomicBool::new(true)),
            notify_is_interactive,
            sigtstp_received,
            fg_job_pid: Arc::new(Mutex::new(None)),
            bg_jobs,
        })
    }

    pub async fn start(&mut self) -> io::Result<()> {
        let _sigtstp_task = self.spawn_sigtstp_task();

        enable_raw_mode()?;
        let _readline_task = self.spawn_readline_task().await;

        while let Some((input, signal)) = self.readline_rx.recv().await {
            self.handle_prompt(input, signal).await?;
        }

        self.handle_exit();
        Ok(())
    }

    pub async fn get_path_executable(&self, name: &str) -> Option<&DirEntry> {
        self.path_executables.iter().find(|e| {
            e.path()
                .components()
                .next_back()
                .and_then(|p| p.as_os_str().to_str())
                == Some(name)
        })
    }

    pub async fn get_local_executable(&self, name: &str) -> Option<DirEntry> {
        let current_dir = std::env::current_dir().ok()?;
        let mut local_executables = vec![];

        let mut dir = read_dir(&current_dir).await.ok()?;
        while let Ok(Some(entry)) = dir.next_entry().await {
            if let Ok(metadata) = entry.metadata().await {
                if (metadata.is_file() || metadata.is_symlink())
                    && metadata.permissions().mode() & 0o111 != 0
                {
                    if entry.file_name() == name {
                        return Some(entry);
                    }
                    local_executables.push(entry);
                }
            }
        }

        None
    }

    pub async fn execute_builtin(&mut self, command: Command) -> io::Result<()> {
        let mut out: &mut (dyn AsyncWrite + Unpin) = match command.stdout_redirect {
            Some(ref out) => {
                &mut open_file_async(out, command.sink.map(|s| s.is_append()).unwrap_or(false))
                    .await?
            }
            None => &mut stdout(),
        };
        let err: &mut (dyn AsyncWrite + Unpin) = match command.stderr_redirect {
            Some(ref err) => {
                &mut open_file_async(err, command.sink.map(|s| s.is_append()).unwrap_or(false))
                    .await?
            }

            None => &mut stderr(),
        };

        let CommandKind::Builtin(kind) = command.kind else {
            return Ok(());
        };
        match kind {
            Builtin::Exit { status_code } => exit(status_code),
            Builtin::Cd { path } => {
                let home = std::env::var("HOME").unwrap();
                let mut cd_path = path.clone();

                if path == "~" {
                    cd_path = home;
                }

                if std::env::set_current_dir(&cd_path).is_err() {
                    err.write_all(format!("cd: {path}: No such file or directory\r\n").as_bytes())
                        .await?;
                }
            }
            Builtin::History => {
                self.dump_history(&mut out).await?;
            }
            Builtin::Jobs => {
                self.show_jobs(&mut out).await?;
            }
            Builtin::Fg(pid) => {
                self.move_job_to_foreground(pid).await?;
            }
        }

        Ok(())
    }

    async fn execute_external_command(
        &mut self,
        name: OsString,
        args: Vec<String>,
    ) -> io::Result<()> {
        let (job, handle) = self.spawn_fg_job(name, args).await?;
        self.block_or_stop(job, handle).await?;

        Ok(())
    }

    async fn block_or_stop(&mut self, mut job: Job, handle: JobHandle) -> io::Result<()> {
        select! {
            Ok(exit_status) = job.wait() => {
                handle.stdin.await?;
                handle.stdout.await?;
                self.last_status = Some(exit_status);
            },
            _ = self.sigtstp_received.notified() => {
                println!("\nReceived Ctrl+Z (SIGTSTP), suspending child...\r");

                job.stop();
                let id = job.id;
                let bg_job = BgJob::new(job, handle);
                self.bg_jobs.insert(id, bg_job);

                set_stdin_blocking()?;
            }
        }

        Ok(())
    }

    async fn dump_history<S: AsyncWrite + Unpin>(&mut self, _sink: &mut S) -> io::Result<()> {
        // [TODO] update this function with regards to the fact that history is now handled by
        // [`Readline`]
        // if let Some(history) = self.history.iter_mut().reduce(|acc, next| {
        //     acc.push_str("\r\n");
        //     acc.push_str(next);
        //     acc
        // }) {
        //     sink.write_all(format!("{}\r\n", history).as_bytes())
        //         .await?;
        // }
        Ok(())
    }

    async fn show_jobs<S: AsyncWrite + Unpin>(&self, out: &mut S) -> io::Result<()> {
        out.write_all(b"Job\tGroup\tState\tCommand\r\n").await?;
        for (id, job) in &self.bg_jobs {
            out.write_all(
                format!(
                    "{}\t{}\t{:?}\t{}\r\n",
                    id,
                    job.job.pid.unwrap_or(0),
                    job.job.state,
                    job.job.name
                )
                .as_bytes(),
            )
            .await?;
        }
        out.flush().await?;
        Ok(())
    }

    async fn move_job_to_foreground(&mut self, id: Option<u32>) -> io::Result<()> {
        let job = match id {
            Some(id) => self.bg_jobs.remove_entry(&(id as usize)),
            None => self.bg_jobs.pop_first(),
        };

        let Some((_, mut job)) = job else {
            return Ok(());
        };

        if job.job.state == JobState::Stopped {
            unsafe {
                libc::kill(job.job.pid.unwrap() as i32, libc::SIGCONT);
            }
        }

        set_stdin_non_blocking()?;
        job.job.resume();
        let BgJob { job, handle } = job;
        self.block_or_stop(job, handle).await?;

        Ok(())
    }

    async fn spawn_job(&mut self, name: OsString, args: Vec<String>) -> io::Result<Job> {
        let size = crossterm::terminal::window_size()?;
        let pty = openpty(
            Some(&Winsize {
                ws_row: size.rows,
                ws_col: size.columns,
                ws_xpixel: 0,
                ws_ypixel: 0,
            }),
            None,
        )?;

        let master_fd = pty.master.as_raw_fd();
        let std_master = unsafe { std::fs::File::from_raw_fd(master_fd) };
        let OpenptyResult { master, slave } = pty;
        std::mem::forget(master);
        let master = tokio::fs::File::from_std(std_master);
        let job = job::Job::new(name, args, &slave, &master, &self.is_interactive).await?;

        Ok(job)
    }

    async fn spawn_fg_job(
        &mut self,
        name: OsString,
        args: Vec<String>,
    ) -> io::Result<(Job, JobHandle)> {
        let mut job = self.spawn_job(name, args).await?;
        *self.fg_job_pid.lock().unwrap() = job.pid;
        let handle = job.spawn().await?;

        Ok((job, handle))
    }

    fn spawn_sigtstp_task(&mut self) -> JoinHandle<()> {
        let sigtstp_cancel = self.cancellation_token.clone();
        let sigtstp_is_interactive = self.is_interactive.clone();
        let fg_job_pid = self.fg_job_pid.clone();
        let sigtstp_received = self.sigtstp_received.clone();
        tokio::spawn(async move {
            let mut sigtstp =
                tokio::signal::unix::signal(SignalKind::from_raw(libc::SIGTSTP)).unwrap();
            while let Some(Some(())) = sigtstp_cancel.run_until_cancelled(sigtstp.recv()).await {
                if !sigtstp_is_interactive.load(Ordering::SeqCst) {
                    let fg_job_pid = fg_job_pid.lock().unwrap();
                    if fg_job_pid.is_some() {
                        unsafe {
                            libc::kill(fg_job_pid.unwrap() as i32, libc::SIGTSTP);
                        }

                        sigtstp_received.notify_one();
                    }
                }
            }
        })
    }

    async fn spawn_readline_task(&mut self) -> JoinHandle<()> {
        let mut readline = Readline::new_with_prompt(DirPrompt).await;
        readline.vim_mode_enabled = true;
        readline.autocomplete_options = self.autocomplete_options.clone();
        let readline_is_interactive = self.is_interactive.clone();
        let readline_cancel = self.cancellation_token.clone();
        let readline_tx = self.readline_tx.clone();
        let notified = self.notify_is_interactive.clone();
        tokio::spawn(async move {
            let mut input = String::new();
            loop {
                if readline_is_interactive.load(Ordering::Acquire) {
                    let read = readline_cancel.run_until_cancelled(readline.read(&mut input));
                    if let Some(Ok(signal)) = read.await {
                        let _ = readline_tx.send((std::mem::take(&mut input), signal));
                    } else {
                        break;
                    }
                }
                notified.notified().await;
            }
        })
    }

    async fn handle_prompt(&mut self, input: String, signal: Signal) -> io::Result<()> {
        if signal == Signal::CtrlD {
            self.handle_exit();
        }
        if !input.is_empty() {
            self.is_interactive.store(false, Ordering::SeqCst);
            match Command::parse(input.trim_start()).await {
                Ok(command) => match command.kind {
                    CommandKind::External { name, args } => {
                        self.execute_external_command(name, args).await?;
                    }
                    _ => {
                        self.execute_builtin(command).await?;
                    }
                },
                Err(_) => {
                    todo!("write error");
                }
            };

            self.is_interactive.store(true, Ordering::SeqCst);
        }
        self.notify_is_interactive.notify_one();

        Ok(())
    }

    fn handle_exit(&mut self) {
        self.cancellation_token.cancel();
        disable_raw_mode().unwrap();
        exit(0);
    }
}

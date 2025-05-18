#![allow(clippy::nonminimal_bool)]

use autocomplete::Trie;
use command::{Command, CommandKind, SinkKind};
use context::{BgContext, Context, FgContext, FgJob, Job, JobRegistry, JobStatus};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use glob::glob;
use prompt::DirPrompt;
use readline::constants::{BUILTINS, DOUBLE_QUOTES_ESCAPE, GLOB};
use readline::signal::Signal;
use readline::Readline;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::process::{exit, ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use tokio::io::{stderr, stdout, AsyncWrite};
use tokio::select;
use tokio::signal::unix::SignalKind;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::{
    fs::{read_dir, DirEntry},
    io::{self, AsyncWriteExt},
    process::Command as SysCommand,
    task,
};
use tokio_util::sync::CancellationToken;
use tty::{disable_cbreak_mode, disable_ctrl_z, enable_cbreak_mode};

pub mod autocomplete;
pub mod command;
mod context;
pub mod prompt;
pub mod readline;
mod tokenizer;
pub mod tty;

#[macro_export]
macro_rules! debug {
    ($($input:tt)*) => {
        disable_raw_mode().unwrap();
        println!($($input)*);
        enable_raw_mode().unwrap();
    };
}

#[allow(unused)]
#[derive(Debug)]
pub struct Shell {
    path: String,
    path_executables: Vec<DirEntry>,
    last_status: Option<ExitStatus>,
    pub autocomplete_options: Trie,

    fg_job: FgJob,
    fg_job_pid: Arc<Mutex<Option<u32>>>,
    bg_jobs: JobRegistry,
    bg_job_remove_channel: UnboundedReceiver<tokio::task::Id>,
    /// Receiving part of channel used to set process id of spawned process
    bg_job_set_pid: UnboundedReceiver<(tokio::task::Id, Option<u32>)>,

    cancellation_token: CancellationToken,
    bg_context: BgContext,

    sigstp: tokio::signal::unix::Signal,
}

impl Shell {
    pub async fn new() -> Self {
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

        let (remove_tx, remove_rx) = tokio::sync::mpsc::unbounded_channel();
        let (pid_tx, pid_rx) = tokio::sync::mpsc::unbounded_channel();
        let cancellation_token = CancellationToken::new();
        let fg_job_pid = Arc::new(Mutex::new(None));
        let context = BgContext::new(remove_tx, pid_tx);
        let sigstp = tokio::signal::unix::signal(SignalKind::from_raw(libc::SIGTSTP)).unwrap();

        Self {
            path,
            path_executables,
            last_status: None,
            autocomplete_options,
            fg_job: Arc::new(tokio::sync::Mutex::new(None)),
            fg_job_pid,
            bg_jobs: HashMap::new(),
            bg_job_remove_channel: remove_rx,
            bg_job_set_pid: pid_rx,
            bg_context: context,
            sigstp,
            cancellation_token,
        }
    }

    pub async fn start(&mut self) -> tokio::io::Result<()> {
        let mut stderr = io::stderr();

        let _ = disable_ctrl_z(&io::stdin());
        let mut readline = Readline::new_with_prompt(DirPrompt).await;
        readline.vim_mode_enabled = true;
        readline.autocomplete_options = self.autocomplete_options.clone();
        let mut input = String::new();
        let mut ctrl_d_scheduled = false;

        enable_raw_mode()?;
        loop {
            select! {
                Some(job_id) = self.bg_job_remove_channel.recv() => {
                    self.handle_bg_job_completition(job_id).await?;
                },
                Some((job_id, pid)) = self.bg_job_set_pid.recv() => {
                    self.update_bg_job_pid(job_id, pid);
                },
                _ = self.sigstp.recv() => {
                    let job_id = self.pause_fg_job().await;
                    if let Some(id) = job_id {
                        println!("Job {id} has been stopped and moved to background");
                    }
                    disable_cbreak_mode()?;
                    enable_raw_mode()?;
                    readline.prompt = Some(DirPrompt);
                }
                fg_job_result = async {
                    if let Some(handle) = self.fg_job.lock().await.as_mut() {
                        Some(handle.await)
                    } else {
                        None
                    }
                }, if self.fg_job.lock().await.is_some() => {
                    if let Some(Ok(Some(Ok(fg_job_result)))) = fg_job_result {
                        self.last_status = Some(fg_job_result);
                    }
                    *self.fg_job.lock().await = None;
                    disable_cbreak_mode()?;
                    enable_raw_mode()?;
                    readline.prompt = Some(DirPrompt);
                    if ctrl_d_scheduled {
                        self.cancellation_token.cancel();
                        // All concurrent futures in this select is cancellation safe, so we are
                        // free to call a break here. If there is currently running fg job,
                        // we manyally wait untill it finishes and only then break out of this
                        // loop.
                        break;
                    }
                }
                signal = readline.read(&mut input) => {
                    if signal? == Signal::CtrlD {
                        if self.fg_job.lock().await.is_some() && !ctrl_d_scheduled {
                            ctrl_d_scheduled = true;
                        } else {
                            self.cancellation_token.cancel();
                            // All concurrent futures in this select is cancellation safe, so we are
                            // free to call a break here. If there is currently running fg job,
                            // we manyally wait untill it finishes and only then break out of this
                            // loop.
                            break;
                        }
                    }

                    if !input.is_empty() {
                        match Command::parse(input.trim_start()).await {
                            Ok(command) => {
                                if (matches!(command.kind, CommandKind::ExternalCommand{..}) && !command.is_bg_job)
                                    || matches!(command.kind, CommandKind::Fg{..}) {
                                    readline.prompt = None;
                                }
                                self.execute(command).await?;
                            },
                            Err(err) => stderr.write_all(format!("{err}\r\n").as_bytes()).await?,
                        }
                        input.clear();
                    }
                },
            }

            if let Some(status) = self.last_status.and_then(|s| s.code()) {
                std::env::set_var("status", status.to_string());
            }
        }

        disable_cbreak_mode()?;
        disable_raw_mode()?;

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

    pub async fn execute(&mut self, command: Command) -> io::Result<()> {
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

        match command.kind {
            CommandKind::Exit { status_code } => exit(status_code),
            CommandKind::ExternalCommand { .. } => {
                if command.is_bg_job {
                    let context = self.bg_context.clone();
                    let job = execute_external_command(self.path.clone(), command, None, context);
                    let handle = tokio::spawn(
                        self.cancellation_token
                            .clone()
                            .run_until_cancelled_owned(job),
                    );
                    self.bg_jobs.insert(handle.id(), Job::new(handle));
                } else {
                    let context = FgContext::new(&self.fg_job_pid);
                    let job = execute_external_command(self.path.clone(), command, None, context);
                    disable_raw_mode()?;
                    enable_cbreak_mode()?;
                    let handle = tokio::spawn(
                        self.cancellation_token
                            .clone()
                            .run_until_cancelled_owned(job),
                    );
                    *self.fg_job.lock().await = Some(handle);
                    // let exit_status =
                    //     execute_external_command(self.path.clone(), command, None, None).await?;
                    // self.last_status = Some(exit_status);
                }
            }
            CommandKind::Cd { path } => {
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
            CommandKind::History => {
                self.dump_history(&mut out).await?;
            }
            CommandKind::Jobs => {
                self.show_jobs(&mut out).await?;
            }
            CommandKind::Fg(pid) => {
                self.move_job_to_foreground(pid).await?;
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

    async fn handle_bg_job_completition(&mut self, job_id: tokio::task::Id) -> io::Result<()> {
        if let Some(job) = self.bg_jobs.remove(&job_id) {
            let res = job.handle.await?;
            if let Some(status) = res {
                self.last_status = Some(status?);
            }
        }
        Ok(())
    }

    fn update_bg_job_pid(&mut self, job_id: tokio::task::Id, pid: Option<u32>) {
        if let Some(job) = self.bg_jobs.get_mut(&job_id) {
            job.pid = pid;
        }
    }

    async fn show_jobs<S: AsyncWrite + Unpin>(&self, out: &mut S) -> io::Result<()> {
        out.write_all(b"Job\tGroup\tStatus\r\n").await?;
        for job in &self.bg_jobs {
            out.write_all(
                format!(
                    "{}\t{}\t{:?}\r\n",
                    job.0,
                    job.1.pid.unwrap_or(0),
                    job.1.status,
                )
                .as_bytes(),
            )
            .await?;
        }
        out.flush().await?;
        Ok(())
    }

    // Pauses currently running forground job and moves it to the background
    async fn pause_fg_job(&mut self) -> Option<tokio::task::Id> {
        let job = self.fg_job.lock().await.take();
        let pid = self.fg_job_pid.lock().unwrap().take();

        let (Some(job), Some(pid)) = (job, pid) else {
            return None;
        };

        unsafe {
            libc::kill(pid as i32, libc::SIGTSTP);
        }

        let id = job.id();
        let mut job = Job::new_with_pid(job, pid);
        job.status = JobStatus::Paused;
        self.bg_jobs.insert(id, job);

        Some(id)
    }

    async fn move_job_to_foreground(&mut self, id: Option<u32>) -> io::Result<()> {
        let job = match id {
            Some(id) => {
                let job_id = self
                    .bg_jobs
                    .iter()
                    .find(|job| job.1.pid == Some(id))
                    .map(|(k, _)| *k);
                match job_id {
                    Some(job_id) => self.bg_jobs.remove(&job_id),
                    None => None,
                }
            }
            None => {
                let random = self.bg_jobs.iter().next().map(|(key, _)| *key);
                if let Some(key) = random {
                    self.bg_jobs.remove(&key)
                } else {
                    None
                }
            }
        };
        if let Some(mut job) = job {
            if self.fg_job.lock().await.is_none() {
                job.status = JobStatus::Running;
                if let Some(pid) = job.pid {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGCONT);
                    }
                }
                *self.fg_job_pid.lock().unwrap() = job.pid;
                disable_raw_mode()?;
                enable_cbreak_mode()?;
                *self.fg_job.lock().await = Some(job.handle);
            }
        } else {
            let mut stderr = io::stderr();
            stderr
                .write_all(b"No jobs where found with given PID\r\n")
                .await?;
            stderr.flush().await?;
        }

        Ok(())
    }
}

fn set_shell_envs() {
    std::env::set_var("COLORTERM", "truecolor");
    std::env::set_var("CLICOLOR", "truecolor");
    std::env::set_var("CLICOLOR_FORCE", "1");
    std::env::set_var("TERM", "tmux-256color");
    std::env::set_var("status", "0");
}

pub fn parse_prompt(args: &str) -> Vec<String> {
    let mut parsed_args = Vec::new();
    let mut current_arg = String::new();
    let mut in_single_quotes = false;
    let mut in_double_quotes = false;

    let mut chars = args.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '|' if !in_single_quotes && !in_double_quotes => {
                parsed_args.push("|".to_string());
            }
            '\'' if !in_double_quotes => in_single_quotes = !in_single_quotes,
            '"' if !in_single_quotes => {
                in_double_quotes = !in_double_quotes;
            }
            '\\' if in_double_quotes || (!in_single_quotes && !in_double_quotes) => {
                if let Some(next_c) = chars.next() {
                    if !in_double_quotes
                        || (in_double_quotes && DOUBLE_QUOTES_ESCAPE.contains(&next_c))
                    {
                        current_arg.push(next_c);
                    } else {
                        current_arg.push(c);
                        current_arg.push(next_c);
                    }
                }
            }
            ' ' if !in_single_quotes && !in_double_quotes => {
                if !current_arg.is_empty() {
                    if current_arg.chars().any(|c| GLOB.contains(&c)) {
                        parsed_args.extend(
                            glob(current_arg.as_str())
                                .into_iter()
                                .flatten()
                                .flatten()
                                .flat_map(|p| p.to_str().map(|s| s.to_string())),
                        );
                    } else {
                        parsed_args.push(current_arg.clone());
                    }
                    current_arg.clear();
                }
            }
            _ => current_arg.push(c),
        }
    }

    if !current_arg.is_empty() {
        if current_arg.chars().any(|c| GLOB.contains(&c)) {
            parsed_args.extend(
                glob(current_arg.as_str())
                    .into_iter()
                    .flatten()
                    .flatten()
                    .flat_map(|p| p.to_str().map(|s| s.to_string())),
            );
        } else {
            parsed_args.push(current_arg.clone());
        }
        current_arg.clear();
    }

    parsed_args
        .into_iter()
        .map(|arg| {
            if arg.starts_with("$") {
                std::env::var(&arg.as_str()[1..]).unwrap_or(arg)
            } else {
                arg
            }
        })
        .collect()
}

async fn populate_path_executables(path: &str) -> Vec<DirEntry> {
    let mut path_executables = Vec::new();
    let mut handles = Vec::new();

    for dir in path.split(':') {
        let dir = dir.to_string();
        let handle = task::spawn(async move {
            let mut entries = Vec::new();
            if let Ok(mut rd) = read_dir(dir).await {
                while let Ok(Some(entry)) = rd.next_entry().await {
                    if let Ok(metadata) = entry.metadata().await {
                        if (metadata.is_file() || metadata.is_symlink())
                            && metadata.permissions().mode() & 0o111 != 0
                        {
                            entries.push(entry);
                        }
                    }
                }
            }
            entries
        });
        handles.push(handle);
    }

    for handle in handles {
        if let Ok(mut entries) = handle.await {
            path_executables.append(&mut entries);
        }
    }

    path_executables
}

fn open_file<P: AsRef<Path>>(path: P, append: bool) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(append)
        .truncate(!append)
        .open(path)
}

async fn open_file_async<P: AsRef<Path>>(path: P, append: bool) -> io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(append)
        .truncate(!append)
        .open(path)
        .await
}

fn execute_external_command<'a, Ctx>(
    path: String,
    command: Command,
    pipe_input: Option<Vec<u8>>,
    context: Ctx,
) -> Pin<Box<dyn Future<Output = io::Result<ExitStatus>> + 'a + Send>>
where
    Ctx: Context + Clone + Send + 'a,
{
    Box::pin(async move {
        let CommandKind::ExternalCommand { name, input } = command.kind else {
            return Ok(ExitStatus::default());
        };
        let canonical_name = canonicalize_path(
            path.clone(),
            name.to_str()
                .ok_or(io::Error::other("Can not convert name to string"))?,
        )
        .ok_or(io::Error::other("Can not canonicalize path"))?;

        let stdout = if command.pipe_to.is_some() {
            Stdio::piped()
        } else {
            command
                .stdout_redirect
                .and_then(|stdout| {
                    open_file(stdout, command.sink == Some(SinkKind::StdoutAppend)).ok()
                })
                .map(Stdio::from)
                .unwrap_or(Stdio::inherit())
        };
        let stderr = command
            .stderr_redirect
            .and_then(|stderr| open_file(stderr, command.sink == Some(SinkKind::StderrAppend)).ok())
            .map(Stdio::from)
            .unwrap_or(Stdio::inherit());

        let stdin = if pipe_input.is_some() {
            Stdio::piped()
        } else {
            Stdio::inherit()
        };

        // disable_raw_mode()?;

        let mut child = SysCommand::new(canonical_name)
            .args(input)
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr)
            .spawn()?;

        let _ = context.set_pid(tokio::task::id(), child.id());

        if let Some(pipe_input) = pipe_input {
            if let Some(ref mut stdin) = child.stdin {
                stdin.write_all(&pipe_input).await?;
            }
        }

        let status = if let Some(sub) = command.pipe_to {
            if let CommandKind::ExternalCommand { .. } = sub.kind {
                let output = child.wait_with_output().await?;
                execute_external_command(
                    path.clone(),
                    *sub.clone(),
                    Some(output.stdout),
                    context.clone(),
                )
                .await?;
                output.status
            } else {
                ExitStatus::default()
            }
        } else {
            child.wait().await?
        };

        // enable_raw_mode()?;

        let _ = context.remove(tokio::task::id());

        Ok(status)
    })
}

pub fn canonicalize_path<P: AsRef<str> + ?Sized>(shell_path: String, path: &P) -> Option<String> {
    for p in shell_path.split(":") {
        if path.as_ref().contains(p) {
            return Some(path.as_ref().replace(p, "").replace("/", ""));
        }
    }
    Some(path.as_ref().to_string())
}

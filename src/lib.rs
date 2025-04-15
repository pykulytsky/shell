#![allow(clippy::nonminimal_bool)]

use autocomplete::Trie;
use command::{Command, CommandKind, Sink};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use prompt::DirPrompt;
use readline::constants::{BUILTINS, DOUBLE_QUOTES_ESCAPE, HISTORY_FILE};
use readline::signal::Signal;
use readline::Readline;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{exit, ExitStatus, Stdio};
use tokio::io::{stderr, stdout, AsyncWrite};
use tokio::{
    fs::{read_dir, DirEntry},
    io::{self, AsyncWriteExt},
    process::Command as SysCommand,
    task,
};

pub mod autocomplete;
pub mod command;
pub mod prompt;
pub mod readline;

#[macro_export]
macro_rules! debug {
    ($($input:tt)*) => {
        disable_raw_mode().unwrap();
        println!($($input)*);
        enable_raw_mode().unwrap();
    };
}

#[derive(Debug, Default)]
pub struct Shell {
    path: String,
    path_executables: Vec<DirEntry>,
    last_status: Option<ExitStatus>,
}

impl Shell {
    pub async fn new() -> Self {
        let path = std::env::var("PATH").unwrap_or_else(|_| "".to_string());
        set_color_envs();
        let path_executables = Self::populate_path_executables(&path).await;

        let mut dictionary = Trie::new();
        dictionary.extend(BUILTINS);
        for path in &path_executables {
            if let Some(p) = path.file_name().to_str() {
                dictionary.insert(p);
            }
        }

        Self {
            path,
            path_executables,
            last_status: None,
        }
    }

    pub async fn start(&mut self) -> tokio::io::Result<()> {
        let mut stderr = io::stderr();

        let mut readline = Readline::new_with_prompt(DirPrompt).await;
        loop {
            let mut input = String::new();
            if readline.read(&mut input).await? == Signal::CtrlD {
                break;
            }

            match Command::parse(input.trim_start(), self) {
                Ok(command) => self.execute(command).await?,
                Err(err) => stderr.write_all(format!("{err}\r\n").as_bytes()).await?,
            }
        }

        let mut history_file = Self::open_file_async(HISTORY_FILE, true).await?;
        readline.dump_history(&mut history_file).await?;

        Ok(())
    }

    fn get_path_executable(&self, name: &str) -> Option<&DirEntry> {
        self.path_executables.iter().find(|e| {
            e.path()
                .components()
                .last()
                .and_then(|p| p.as_os_str().to_str())
                == Some(name)
        })
    }

    pub async fn execute(&mut self, command: Command) -> io::Result<()> {
        let mut out: Box<dyn AsyncWrite + Unpin> = match command.stdout_redirect {
            Some(ref out) => Box::new(
                Shell::open_file_async(out, command.sink.map(|s| s.is_append()).unwrap_or(false))
                    .await?,
            ),
            None => Box::new(stdout()),
        };
        let mut err: Box<dyn AsyncWrite + Unpin> = match command.stderr_redirect {
            Some(ref err) => Box::new(
                Shell::open_file_async(err, command.sink.map(|s| s.is_append()).unwrap_or(false))
                    .await?,
            ),
            None => Box::new(stderr()),
        };

        match command.kind {
            CommandKind::Exit { status_code } => exit(status_code),
            CommandKind::ExternalCommand { name, input } => {
                let canonicalized_name = self
                    .canonicalize_path(
                        name.to_str()
                            .ok_or(io::Error::other("Can not convert name to string"))?,
                    )
                    .ok_or(io::Error::other("Can not canonicalize path"))?;
                disable_raw_mode()?;
                let stdout = command
                    .stdout_redirect
                    .and_then(|stdout| {
                        Self::open_file(stdout, command.sink == Some(Sink::StdoutAppend)).ok()
                    })
                    .map(Stdio::from)
                    .unwrap_or(Stdio::inherit());
                let stderr = command
                    .stderr_redirect
                    .and_then(|stderr| {
                        Self::open_file(stderr, command.sink == Some(Sink::StderrAppend)).ok()
                    })
                    .map(Stdio::from)
                    .unwrap_or(Stdio::inherit());

                let mut child = SysCommand::new(canonicalized_name)
                    .args(input)
                    .stdin(Stdio::inherit())
                    .stdout(stdout)
                    .stderr(stderr)
                    .spawn()?;

                let status = child.wait().await?;
                enable_raw_mode()?;
                self.last_status = Some(status);
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
        }

        Ok(())
    }

    pub fn canonicalize_path<P: AsRef<str> + ?Sized>(&self, path: &P) -> Option<String> {
        for p in self.path.split(":") {
            if path.as_ref().contains(p) {
                return Some(path.as_ref().replace(p, "").replace("/", ""));
            }
        }
        Some(path.as_ref().to_string())
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
                        parsed_args.push(current_arg.clone());
                        current_arg.clear();
                    }
                }
                _ => current_arg.push(c),
            }
        }

        if !current_arg.is_empty() {
            parsed_args.push(current_arg);
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

    async fn dump_history<S: AsyncWrite + Unpin>(&mut self, _sink: &mut S) -> io::Result<()> {
        // [TODO] update this function with regards to the fact that history is now handled by
        // `Readline`
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
}

fn set_color_envs() {
    std::env::set_var("COLORTERM", "truecolor");
    std::env::set_var("CLICOLOR", "truecolor");
    std::env::set_var("CLICOLOR_FORCE", "1");
    std::env::set_var("TERM", "tmux-256color");
}

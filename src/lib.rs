#![allow(clippy::nonminimal_bool)]

use crossterm::terminal::disable_raw_mode;
use crossterm::terminal::enable_raw_mode;
use std::os::unix::fs::PermissionsExt;
use std::process::exit;
use tokio::fs::DirEntry;
use tokio::io::AsyncReadExt;
use tokio::select;
use tokio::task;
use utils::normalize_output;
use utils::ARROW_ANCHOR;
use utils::BACKSPACE;
use utils::CTRL_C;
use utils::CTRL_D;
pub mod command;
mod utils;
use tokio::process::Command as SysCommand;

use command::{Command, CommandKind};
use tokio::{
    fs::read_dir,
    io::{self, AsyncWriteExt},
    signal,
};
use utils::DOUBLE_QUOTES_ESCAPE;

#[derive(Debug, Default)]
pub struct Shell {
    pub path: String,
    pub path_executables: Vec<DirEntry>,
    pub history: Vec<String>,
}

impl Shell {
    pub async fn new() -> Self {
        let path = std::env::var("PATH").unwrap_or_else(|_| "".to_string());

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

        Self {
            path,
            path_executables,
            history: vec![],
        }
    }

    pub async fn start(&mut self) -> tokio::io::Result<()> {
        enable_raw_mode()?;

        let mut stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        let mut input = Vec::new();
        let mut arrow_buffer = [0u8; 2];
        let mut last_pressed = 0;

        loop {
            if input.is_empty() && last_pressed != BACKSPACE {
                stdout.write_all(b"$ ").await?;
            }
            stdout.flush().await?;

            select! {
                n = stdin.read_u8() => {
                    if let Ok(byte) = n {
                        last_pressed = byte;
                        match byte {
                            b'\r' | b'\n' => {
                                stdout.write_all(b"\r\n").await?;
                                stdout.flush().await?;

                                if !input.is_empty() {
                                    let command_str = String::from_utf8_lossy(&input);
                                    match Command::read(command_str.trim_start(), self).await {
                                        Ok(command) => self.run(command).await?,
                                        Err(err) => stderr.write_all(format!("{err}\r\n").as_bytes()).await?,
                                    }
                                    self.history.push(command_str.to_string());
                                }
                                input.clear();
                            },
                            CTRL_C => {
                                stdout.write_all(b"\r\n").await?;
                                stdout.flush().await?;
                            },
                            CTRL_D => {
                                input.clear();
                                break;
                            },
                            BACKSPACE => {
                                if !input.is_empty() {
                                    input.pop();
                                    stdout.write_all(b"\x08 \x08").await?;
                                }
                            },
                            ARROW_ANCHOR => {
                                if stdin.read_exact(&mut arrow_buffer).await.is_ok() {
                                    // match arrow_buffer {
                                        // [91, 65] => stdout.write_all(b"Up Arrow\r\n").await?,
                                        // [91, 66] => stdout.write_all(b"Down Arrow\r\n").await?,
                                        // [91, 67] => stdout.write_all(b"Right Arrow\r\n").await?,
                                        // [91, 68] => stdout.write_all(b"Left Arrow\r\n").await?,
                                        // _ => {}
                                    // }
                                }
                            },
                            _ => {
                                input.push(byte);
                                stdout.write_all(&[byte]).await?;
                            }
                        }
                    }
                },
                _ = signal::ctrl_c() => {
                    stdout.write_all(b"\r\n").await?;
                    stdout.flush().await?;
                }
            }
        }
        disable_raw_mode()?;
        Ok(())
    }

    fn get_path_executable(&self, name: &str) -> Option<&DirEntry> {
        self.path_executables
            .iter()
            .find(|e| e.path().components().last().unwrap().as_os_str() == name)
    }

    pub async fn run(&self, mut command: Command) -> io::Result<()> {
        match command.kind {
            CommandKind::Exit { status_code } => exit(status_code),
            CommandKind::Echo { msg } => {
                command
                    .out
                    .write_all(format!("{}\r\n", msg.join(" ")).as_bytes())
                    .await?;
            }
            CommandKind::Type { arg } => match arg.as_ref() {
                c if matches!(c, "exit" | "echo" | "type" | "pwd") => {
                    command
                        .out
                        .write_all(format!("{c} is a shell builtin\r\n").as_bytes())
                        .await?;
                }
                c if self.get_path_executable(c).is_some() => {
                    let entry = self.get_path_executable(c).unwrap();
                    command
                        .out
                        .write_all(
                            format!("{c} is {}\r\n", entry.path().as_path().to_string_lossy())
                                .as_bytes(),
                        )
                        .await?;
                }
                c => {
                    command
                        .err
                        .write_all(format!("{c}: not found\r\n").as_bytes())
                        .await?;
                }
            },
            CommandKind::Pwd => {
                let pwd = std::env::current_dir()?;
                command
                    .out
                    .write_all(format!("{}\r\n", pwd.display()).as_bytes())
                    .await?;
            }
            CommandKind::ExternalCommand { name, input } => {
                let canonicalized_name = self.canonicalize_path(name.to_str().unwrap()).unwrap();
                let output = SysCommand::new(canonicalized_name)
                    .args(input)
                    .output()
                    .await?;
                command
                    .out
                    .write_all(normalize_output(output.stdout).as_ref())
                    .await?;
                command
                    .err
                    .write_all(normalize_output(output.stderr).as_ref())
                    .await?;
            }
            CommandKind::Cd { path } => {
                let home = std::env::var("HOME").unwrap();
                let mut cd_path = path.clone();

                if path == "~" {
                    cd_path = home;
                }

                if std::env::set_current_dir(&cd_path).is_err() {
                    command
                        .err
                        .write_all(format!("cd: {path}: No such file or directory\r\n").as_bytes())
                        .await?;
                }
            }
            CommandKind::History => {
                command
                    .out
                    .write_all(format!("{}\r\n", self.history.join("\r\n")).as_bytes())
                    .await?
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

    pub fn parse_args(args: &str) -> Vec<String> {
        let mut parsed_args = Vec::new();
        let mut current_arg = String::new();
        let mut in_single_quotes = false;
        let mut in_double_quotes = false;

        let mut chars = args.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
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
    }
}

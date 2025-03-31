use std::os::unix::fs::PermissionsExt;
use std::process::exit;
use tokio::fs::DirEntry;
use tokio::io::AsyncBufReadExt;
use tokio::io::BufReader;
use tokio::select;
use tokio::task;
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
        }
    }

    pub async fn start(&mut self) {
        let mut stdin = BufReader::new(io::stdin());
        let mut stdout = io::stdout();

        let mut input = String::new();

        loop {
            stdout.write_all("$ ".as_bytes()).await.unwrap();
            stdout.flush().await.unwrap();
            select! {
            _ = stdin.read_line(&mut input) => {
                    if input != "\n" {
                        match Command::read(input[..input.len() - 1].trim_start(), self).await {
                            Ok(command) => self.run(command).await,
                            Err(err) => eprintln!("{err}"),
                        }
                    }
                },
            _ = signal::ctrl_c() => {
                    stdout.write_all(b"\n").await.unwrap();
                    stdout.flush().await.unwrap();
                }
            }
            input.clear();
        }
    }

    fn get_path_executable(&self, name: &str) -> Option<&DirEntry> {
        self.path_executables
            .iter()
            .find(|e| e.path().components().last().unwrap().as_os_str() == name)
    }

    pub async fn run(&self, mut command: Command) {
        match command.kind {
            CommandKind::Exit { status_code } => exit(status_code),
            CommandKind::Echo { msg } => {
                command
                    .out
                    .write_all(format!("{}\n", msg.join(" ")).as_bytes())
                    .await
                    .unwrap();
            }
            CommandKind::Type { arg } => match arg.as_ref() {
                c if matches!(c, "exit" | "echo" | "type" | "pwd") => {
                    command
                        .out
                        .write_all(format!("{c} is a shell builtin").as_bytes())
                        .await
                        .unwrap();
                }
                c if self.get_path_executable(c).is_some() => {
                    let entry = self.get_path_executable(c).unwrap();
                    command
                        .out
                        .write_all(
                            format!("{c} is {}", entry.path().as_path().to_string_lossy())
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                }
                c => {
                    command
                        .err
                        .write_all(format!("{c}: not found").as_bytes())
                        .await
                        .unwrap();
                }
            },
            CommandKind::Pwd => {
                let pwd = std::env::current_dir().unwrap();
                command
                    .out
                    .write_all(format!("{}", pwd.display()).as_bytes())
                    .await
                    .unwrap();
            }
            CommandKind::Program { name, input } => {
                let canonicalized_name = self.canonicalize_path(name.to_str().unwrap()).unwrap();
                let output = SysCommand::new(canonicalized_name)
                    .args(input)
                    .output()
                    .await
                    .unwrap();
                command.out.write_all(&output.stdout).await.unwrap();
                command.err.write_all(&output.stderr).await.unwrap();
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
                        .write_all(format!("cd: {path}: No such file or directory").as_bytes())
                        .await
                        .unwrap();
                }
            }
        }
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

#![allow(clippy::nonminimal_bool)]

use autocomplete::Trie;
use command::{Command, CommandKind};
use crossterm::cursor::MoveLeft;
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use std::os::unix::fs::PermissionsExt;
use std::process::{exit, Stdio};
use tokio::{
    fs::{read_dir, DirEntry},
    io::{self, AsyncReadExt, AsyncWriteExt, Stdout},
    process::Command as SysCommand,
    select, signal, task,
};
use utils::{
    normalize_output, ARROW_ANCHOR, BACKSPACE, BUILTINS, CTRL_C, CTRL_D, DOUBLE_QUOTES_ESCAPE,
    DOWN_ARROW, LEFT_ARROW, RIGHT_ARROW, SHOULD_NOT_REDRAW_PROMPT, UP_ARROW,
};

pub mod autocomplete;
pub mod command;
mod utils;

#[derive(Debug, Default)]
pub struct Shell {
    pub path: String,
    pub path_executables: Vec<DirEntry>,
    pub history: Vec<String>,
    pub dictionary: Trie,
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
            history: vec![],
            dictionary,
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
        let mut input_cursor = 0;
        let mut curr_autocomplete_options: Vec<String> = vec![];
        let mut autocomplete_cursor: isize = 0;

        loop {
            if input.is_empty() && !SHOULD_NOT_REDRAW_PROMPT.contains(&last_pressed) {
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
                                input_cursor = 0;
                            },
                            CTRL_C => {
                                input.clear();
                                input_cursor = 0;
                                stdout.write_all(b"\r\n").await?;
                                stdout.flush().await?;
                            },
                            CTRL_D => {
                                input.clear();
                                break;
                            },
                            BACKSPACE => {
                                // TODO: fix bug with deleting first charachter
                                if input_cursor != 0 {
                                    input_cursor -= 1;
                                    input.remove(input_cursor);
                                    if input_cursor == input.len() {
                                        stdout.write_all(b"\x08 \x08").await?;
                                    } else {
                                        let mut temp_buf = vec![];
                                        execute!(temp_buf, Clear(ClearType::CurrentLine)).unwrap();
                                        stdout.write_all(&temp_buf).await?;
                                        stdout.write_all(b"\r$ ").await?;
                                        stdout.write_all(&input).await?;
                                        temp_buf.clear();
                                        execute!(temp_buf, MoveLeft(1)).unwrap();
                                        stdout.write_all(&temp_buf).await?;
                                        stdout.flush().await?;
                                    }
                                }
                            },
                            ARROW_ANCHOR => {
                                if stdin.read_exact(&mut arrow_buffer).await.is_ok() {
                                    match arrow_buffer {
                                        UP_ARROW => {
                                            // stdout.write_all(&[ARROW_ANCHOR, UP_ARROW[0], UP_ARROW[1]]).await?;
                                        },
                                        DOWN_ARROW => {
                                            // stdout.write_all(&[ARROW_ANCHOR, DOWN_ARROW[0], DOWN_ARROW[1]]).await?;
                                        },
                                        RIGHT_ARROW if input_cursor < input.len() => {
                                                stdout.write_all(&[ARROW_ANCHOR, RIGHT_ARROW[0], RIGHT_ARROW[1]]).await?;
                                                input_cursor += 1;
                                        },
                                        LEFT_ARROW  if input_cursor != 0 => {
                                            input_cursor -= 1;
                                            stdout.write_all(&[ARROW_ANCHOR, LEFT_ARROW[0], LEFT_ARROW[1]]).await?;
                                        },
                                        _ => {}
                                    }
                                }
                            },
                            b'\t' => {
                                self.handle_autocomplete(&mut input, &mut input_cursor, &mut curr_autocomplete_options, &mut autocomplete_cursor, &mut stdout).await;
                            }
                            _ => {
                                input.push(byte);
                                input_cursor += 1;
                                stdout.write_all(&[byte]).await?;
                                autocomplete_cursor = 0;
                                curr_autocomplete_options.clear();
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
                disable_raw_mode()?;
                let mut child = SysCommand::new(canonicalized_name)
                    .args(input)
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .spawn()?;

                let status = child.wait().await?;
                enable_raw_mode()?;

                // optional: check exit status
                if !status.success() {
                    // handle non-zero exit code
                }
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

    async fn handle_autocomplete(
        &self,
        input: &mut Vec<u8>,
        cursor: &mut usize,
        autocomplete_options: &mut Vec<String>,
        autocomplete_cursor: &mut isize,
        stdout: &mut Stdout,
    ) {
        let command_str = std::str::from_utf8(input).unwrap();

        if !autocomplete_options.is_empty() {
            if *autocomplete_cursor < 0 {
                *autocomplete_cursor = autocomplete_options.len() as isize - 1;
            }
            let Some(suffix) = autocomplete_options
                .get(*autocomplete_cursor as usize)
                .map(|o| o.to_string())
            else {
                return;
            };

            stdout.write_all(b"\r\x1b[K$ ").await.unwrap();
            stdout.write_all(suffix.as_bytes()).await.unwrap();
            stdout.write_u8(b' ').await.unwrap();

            input.clear();
            input.extend(suffix.as_bytes());
            input.push(b' ');

            *autocomplete_cursor -= 1;
            *cursor = suffix.len() + 1;
            return;
        }

        let suggestions = self.dictionary.suggest(command_str);
        if suggestions.is_empty() {
            return;
        }

        let suffix = &suggestions[0].clone()[command_str.len()..];
        stdout.write_all(suffix.as_bytes()).await.unwrap();
        stdout.write_u8(b' ').await.unwrap();

        for c in suffix.chars() {
            input.push(c as u8);
        }
        input.push(b' ');

        *autocomplete_options = suggestions;
        *autocomplete_cursor = autocomplete_options.len() as isize - 1;
        *cursor += suffix.len() + 1;
    }
}

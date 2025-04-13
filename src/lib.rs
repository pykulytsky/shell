#![allow(clippy::nonminimal_bool)]

use autocomplete::Trie;
use command::{Command, CommandKind, Sink};
use crossterm::cursor::{MoveLeft, MoveRight};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType};
use readline::constants::{
    ARROW_ANCHOR, BACKSPACE, BUILTINS, CTRL_C, CTRL_D, CTRL_LEFT_ARROW, CTRL_RIGHT_ARROW,
    DOUBLE_QUOTES_ESCAPE, DOWN_ARROW, HISTORY_FILE, LEFT_ARROW, RIGHT_ARROW,
    SHOULD_NOT_REDRAW_PROMPT, UP_ARROW,
};
use std::collections::VecDeque;
use std::env::current_dir;
use std::fs::File;
use std::fs::OpenOptions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{exit, ExitStatus, Stdio};
use tokio::io::{stderr, stdout, AsyncWrite};
use tokio::{
    fs::{read_dir, DirEntry},
    io::{self, AsyncReadExt, AsyncWriteExt, Stdout},
    process::Command as SysCommand,
    select, signal, task,
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

#[derive(Debug)]
enum HistoryDirection {
    Up,
    Down,
}

#[derive(Debug, Default)]
pub struct Shell {
    pub prompt: Vec<u8>,
    pub prompt_cursor: usize,
    pub path: String,
    pub path_executables: Vec<DirEntry>,
    pub history: VecDeque<String>,
    pub history_cursor: Option<usize>,
    pub dictionary: Trie,
    pub last_status: Option<ExitStatus>,
}

impl Shell {
    pub async fn new() -> Self {
        let path = std::env::var("PATH").unwrap_or_else(|_| "".to_string());
        let path_executables = Self::populate_path_executables(&path).await;

        let mut dictionary = Trie::new();
        dictionary.extend(BUILTINS);
        for path in &path_executables {
            if let Some(p) = path.file_name().to_str() {
                dictionary.insert(p);
            }
        }

        let history = tokio::fs::read_to_string(HISTORY_FILE)
            .await
            .unwrap_or(String::new());

        Self {
            prompt: Vec::new(),
            prompt_cursor: 0,
            path,
            path_executables,
            history: history.lines().map(|l| l.to_string()).collect(),
            history_cursor: None,
            dictionary,
            last_status: None,
        }
    }

    pub async fn start(&mut self) -> tokio::io::Result<()> {
        enable_raw_mode()?;

        let mut stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut stderr = io::stderr();
        let mut arrow_buffer = [0u8; 2];
        let mut ctrl_arrow_buffer = [0u8; 2];
        let mut last_pressed = 0;

        let mut curr_autocomplete_options: Vec<String> = vec![];
        let mut autocomplete_cursor: isize = 0;

        loop {
            if self.prompt.is_empty() && !SHOULD_NOT_REDRAW_PROMPT.contains(&last_pressed) {
                render_prompt(&mut stdout).await?;
            }
            stdout.flush().await?;

            // TODO: move to separate module
            select! {
                n = stdin.read_u8() => {
                    if let Ok(byte) = n {
                        last_pressed = byte;
                        match byte {
                            b'\r' | b'\n' => {
                                self.history_cursor = None;
                                stdout.write_all(b"\r\n").await?;
                                stdout.flush().await?;

                                if !self.prompt.is_empty() {
                                    let p = &self.prompt.clone();
                                    let command_str = String::from_utf8_lossy(p);
                                    match Command::parse(command_str.trim_start(), self) {
                                        Ok(command) => self.run(command).await?,
                                        Err(err) => stderr.write_all(format!("{err}\r\n").as_bytes()).await?,
                                    }
                                    if self.history_cursor.is_none() {
                                        self.history.push_front(command_str.to_string());
                                    }
                                }
                                self.prompt.clear();
                                self.prompt_cursor = 0;
                            },
                            CTRL_C => {
                                self.prompt.clear();
                                self.prompt_cursor = 0;
                                self.history_cursor = None;
                                stdout.write_all(b"\r\n").await?;
                                stdout.flush().await?;
                            },
                            CTRL_D => {
                                self.prompt.clear();
                                self.history_cursor = None;
                                break;
                            },
                            BACKSPACE => {
                                self.history_cursor = None;
                                // TODO: fix bug with deleting first charachter
                                if self.prompt_cursor != 0 {
                                    self.prompt_cursor -= 1;
                                    self.prompt.remove(self.prompt_cursor);
                                    if self.prompt_cursor == self.prompt.len() {
                                        stdout.write_all(b"\x08 \x08").await?;
                                    } else {
                                        let mut temp_buf = vec![];
                                        execute!(temp_buf, Clear(ClearType::CurrentLine))?;
                                        stdout.write_all(&temp_buf).await?;
                                        stdout.write_all(b"\r").await?;
                                        render_prompt(&mut stdout).await?;
                                        stdout.write_all(&self.prompt).await?;
                                        temp_buf.clear();
                                        execute!(temp_buf, MoveLeft((self.prompt.len() - self.prompt_cursor) as u16))?;
                                        stdout.write_all(&temp_buf).await?;
                                        stdout.flush().await?;
                                    }
                                }
                            },
                            ARROW_ANCHOR => {
                                if stdin.read_exact(&mut arrow_buffer).await.is_ok() {
                                    match arrow_buffer {
                                        UP_ARROW => {
                                            self.handle_history_change(HistoryDirection::Up, &mut stdout).await?;
                                        },
                                        DOWN_ARROW => {
                                            self.handle_history_change(HistoryDirection::Down, &mut stdout).await?;
                                        },
                                        RIGHT_ARROW if self.prompt_cursor < self.prompt.len() => {
                                                stdout.write_all(&[ARROW_ANCHOR, RIGHT_ARROW[0], RIGHT_ARROW[1]]).await?;
                                                self.prompt_cursor += 1;
                                        },
                                        LEFT_ARROW if self.prompt_cursor != 0 => {
                                            self.prompt_cursor -= 1;
                                            stdout.write_all(&[ARROW_ANCHOR, LEFT_ARROW[0], LEFT_ARROW[1]]).await?;
                                        },
                                        _ => {}
                                    }
                                }
                            },
                            b';' => {
                                if stdin.read_exact(&mut ctrl_arrow_buffer).await.is_ok() {
                                    match ctrl_arrow_buffer {
                                        CTRL_LEFT_ARROW if self.prompt_cursor != 0 => {
                                            self.move_cursor_word_left(&mut stdout).await?;
                                        }
                                        CTRL_RIGHT_ARROW if self.prompt_cursor < self.prompt.len() => {
                                            self.move_cursor_word_right(&mut stdout).await?;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            b'\t' => {
                                self.handle_autocomplete(&mut curr_autocomplete_options, &mut autocomplete_cursor, &mut stdout).await?;
                            }
                            _ => {
                                if !self.prompt.is_empty() && self.prompt_cursor != self.prompt.len() {
                                    self.prompt.insert(self.prompt_cursor, byte);
                                        let mut temp_buf = vec![];
                                        execute!(temp_buf, Clear(ClearType::CurrentLine))?;
                                        stdout.write_all(&temp_buf).await?;
                                        stdout.write_all(b"\r").await?;
                                        render_prompt(&mut stdout).await?;
                                        stdout.write_all(&self.prompt).await?;
                                        temp_buf.clear();
                                        execute!(temp_buf, MoveLeft((self.prompt.len() - self.prompt_cursor - 1) as u16))?;
                                        stdout.write_all(&temp_buf).await?;
                                        stdout.flush().await?;
                                } else {
                                    self.prompt.push(byte);
                                    stdout.write_all(&[byte]).await?;
                                }
                                self.prompt_cursor += 1;
                                self.history_cursor = None;
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

        let mut history_file = Self::open_file_async(HISTORY_FILE, true).await?;
        self.dump_history(&mut history_file).await?;

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

    pub async fn run(&mut self, command: Command) -> io::Result<()> {
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
    }

    async fn handle_autocomplete(
        &mut self,
        autocomplete_options: &mut Vec<String>,
        autocomplete_cursor: &mut isize,
        stdout: &mut Stdout,
    ) -> io::Result<()> {
        let command_str = std::str::from_utf8(&self.prompt)
            .map_err(|_| io::Error::other("Input is not valid utf-8"))?;

        if !autocomplete_options.is_empty() {
            if *autocomplete_cursor < 0 {
                *autocomplete_cursor = autocomplete_options.len() as isize - 1;
            }
            let Some(suffix) = autocomplete_options
                .get(*autocomplete_cursor as usize)
                .map(|o| o.to_string())
            else {
                return Ok(());
            };

            stdout.write_all(b"\r\x1b[K").await?;
            render_prompt(stdout).await?;
            stdout.write_all(suffix.as_bytes()).await?;
            stdout.write_u8(b' ').await?;

            self.prompt.clear();
            self.prompt.extend(suffix.as_bytes());
            self.prompt.push(b' ');

            *autocomplete_cursor -= 1;
            self.prompt_cursor = suffix.len() + 1;
            return Ok(());
        }

        let suggestions = self.dictionary.suggest(command_str);
        if suggestions.is_empty() {
            return Ok(());
        }

        let suffix = &suggestions[0].clone()[command_str.len()..];
        stdout.write_all(suffix.as_bytes()).await?;
        stdout.write_u8(b' ').await?;

        for c in suffix.chars() {
            self.prompt.push(c as u8);
        }
        self.prompt.push(b' ');

        *autocomplete_options = suggestions;
        *autocomplete_cursor = autocomplete_options.len() as isize - 1;
        self.prompt_cursor += suffix.len() + 1;

        Ok(())
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

    async fn handle_history_change<S: AsyncWrite + Unpin>(
        &mut self,
        to: HistoryDirection,
        sink: &mut S,
    ) -> io::Result<()> {
        let command: Option<&String> = match (to, &mut self.history_cursor) {
            (HistoryDirection::Up, None) if !self.history.is_empty() => {
                let command = self.history.front();
                self.history_cursor = Some(0);
                command
            }
            (HistoryDirection::Up, Some(ref mut cursor)) => {
                let command = self.history.get(*cursor + 1);
                *cursor += 1;
                command
            }
            (HistoryDirection::Down, Some(ref mut cursor)) => {
                let command = self.history.get(*cursor - 1);
                *cursor -= 1;
                command
            }
            _ => None,
        };

        let Some(command) = command.cloned() else {
            if self.history.is_empty() && self.history_cursor.is_some() {
                self.history_cursor = None;
            }
            return Ok(());
        };

        self.prompt.clear();
        self.prompt.extend_from_slice(command.as_bytes());
        self.prompt_cursor = self.prompt.len();
        sink.write_all(b"\r\x1b[K").await?;
        render_prompt(sink).await?;
        sink.write_all(command.as_bytes()).await?;

        Ok(())
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

    pub async fn dump_history<S: AsyncWrite + Unpin>(&mut self, sink: &mut S) -> io::Result<()> {
        if let Some(history) = self.history.iter_mut().reduce(|acc, next| {
            acc.push_str("\r\n");
            acc.push_str(next);
            acc
        }) {
            sink.write_all(format!("{}\r\n", history).as_bytes())
                .await?;
        }
        Ok(())
    }

    async fn move_cursor_word_left<S: AsyncWrite + Unpin>(
        &mut self,
        sink: &mut S,
    ) -> io::Result<()> {
        let mut temp_buf = vec![];
        if let Some(pos) = self.prompt[..self.prompt_cursor - 1]
            .iter()
            .rposition(|c| *c == b' ')
        {
            execute!(
                temp_buf,
                MoveLeft(self.prompt_cursor as u16 - pos as u16 - 1)
            )?;
            self.prompt_cursor = pos + 1;
        } else {
            execute!(temp_buf, MoveLeft(self.prompt_cursor as u16))?;
            self.prompt_cursor = 0;
        }
        sink.write_all(&temp_buf).await?;
        Ok(())
    }

    async fn move_cursor_word_right<S: AsyncWrite + Unpin>(
        &mut self,
        sink: &mut S,
    ) -> io::Result<()> {
        let mut temp_buf = vec![];
        if let Some(pos) = self.prompt[self.prompt_cursor + 1..]
            .iter()
            .position(|c| *c == b' ')
        {
            execute!(temp_buf, MoveRight(pos as u16 + 1))?;
            self.prompt_cursor = pos + self.prompt_cursor + 1;
        } else {
            execute!(
                temp_buf,
                MoveRight(self.prompt.len() as u16 - self.prompt_cursor as u16)
            )?;
            self.prompt_cursor = self.prompt.len();
        }
        sink.write_all(&temp_buf).await?;
        Ok(())
    }
}

async fn render_prompt<S: AsyncWrite + Unpin>(sink: &mut S) -> io::Result<()> {
    let current_dir = current_dir()?;
    let dir_name = current_dir
        .file_name()
        .unwrap_or_else(|| current_dir.as_os_str())
        .to_string_lossy();

    sink.write_all(dir_name.as_bytes()).await?;
    sink.write_u8(b' ').await?;

    Ok(())
}

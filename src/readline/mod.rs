use crate::{
    autocomplete::Trie,
    prompt::{DefaultPrompt, Prompt},
    readline::constants::{
        ARROW_ANCHOR, BACKSPACE, CTRL_C, CTRL_D, CTRL_LEFT_ARROW, CTRL_RIGHT_ARROW, DOWN_ARROW,
        HISTORY_FILE, LEFT_ARROW, RIGHT_ARROW, SHOULD_NOT_REDRAW_PROMPT, UP_ARROW,
    },
};

#[derive(Debug)]
pub enum HistoryDirection {
    Up,
    Down,
}

use crossterm::{
    cursor::{MoveLeft, MoveRight},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
};
use std::collections::VecDeque;
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    select,
};

pub mod constants;
pub mod signal;

use signal::Signal;

#[derive(Debug)]
pub struct Readline<P> {
    pub prompt: Option<P>,
    pub input: Vec<u8>,
    pub input_cursor: usize,
    pub history: VecDeque<String>,
    pub history_cursor: Option<usize>,
    pub dictionary: Trie,
    pub last_pressed: Option<u8>,
}

impl Readline<DefaultPrompt> {
    pub async fn new() -> Readline<DefaultPrompt> {
        let history = tokio::fs::read_to_string(HISTORY_FILE)
            .await
            .unwrap_or(String::new());

        Readline {
            input: vec![],
            input_cursor: 0,
            history: history.lines().map(|l| l.to_string()).collect(),
            history_cursor: None,
            dictionary: Trie::new(),
            last_pressed: None,
            prompt: None,
        }
    }
}

impl<P: Prompt> Readline<P> {
    pub async fn new_with_prompt(prompt: P) -> Readline<P> {
        let history = tokio::fs::read_to_string(HISTORY_FILE)
            .await
            .unwrap_or(String::new());

        Readline::<P> {
            input: vec![],
            input_cursor: 0,
            history: history.lines().map(|l| l.to_string()).collect(),
            history_cursor: None,
            dictionary: Trie::new(),
            last_pressed: None,
            prompt: Some(prompt),
        }
    }

    pub async fn read(&mut self, input: &mut String) -> io::Result<Signal> {
        enable_raw_mode()?;

        let mut stdin = io::stdin();
        let mut stdout = io::stdout();
        let mut arrow_buffer = [0u8; 2];
        let mut ctrl_arrow_buffer = [0u8; 2];

        let mut curr_autocomplete_options: Vec<String> = vec![];
        let mut autocomplete_cursor: isize = 0;
        let mut signal = Signal::Success;

        loop {
            if let Some(prompt) = &self.prompt {
                if self.input.is_empty()
                    && !SHOULD_NOT_REDRAW_PROMPT.contains(&self.last_pressed.unwrap_or(0))
                {
                    prompt.draw(&mut stdout).await?;
                }
            }
            stdout.flush().await?;

            select! {
                n = stdin.read_u8() => {
                    if let Ok(byte) = n {
                        self.last_pressed = Some(byte);
                        match byte {
                            b'\r' | b'\n' => {
                                self.history_cursor = None;
                                stdout.write_all(b"\r\n").await?;
                                stdout.flush().await?;

                                if !self.input.is_empty() {
                                    let p = &self.input.clone();
                                    let command_str = String::from_utf8_lossy(p);
                                    if self.history_cursor.is_none() {
                                        self.history.push_front(command_str.to_string());
                                    }
                                    *input = command_str.to_string();
                                }
                                self.input.clear();
                                self.input_cursor = 0;
                                break;
                            },
                            CTRL_C => {
                                self.handle_ctrl_c(&mut stdout).await?;
                            },
                            CTRL_D => {
                                self.handle_ctrl_d();
                                signal = Signal::CtrlD;
                                break;
                            },
                            BACKSPACE => {
                                self.handle_backspace(&mut stdout).await?;
                            },
                            ARROW_ANCHOR => {
                                self.handle_arrows(&mut stdout, &mut stdin, &mut arrow_buffer).await?;
                            },
                            b';' => {
                                if stdin.read_exact(&mut ctrl_arrow_buffer).await.is_ok() {
                                    match ctrl_arrow_buffer {
                                        CTRL_LEFT_ARROW if self.input_cursor != 0 => {
                                            self.move_cursor_word_left(&mut stdout).await?;
                                        }
                                        CTRL_RIGHT_ARROW if self.input_cursor < self.input.len() => {
                                            self.move_cursor_word_right(&mut stdout).await?;
                                        }
                                        _ => { }
                                    }
                                }
                            }
                            b'\t' => {
                                self.handle_autocomplete(&mut curr_autocomplete_options, &mut autocomplete_cursor, &mut stdout).await?;
                            }
                            _ => {
                                self.handle_char(&mut stdout, byte).await?;
                            }
                        }
                    }
                },
                _ = tokio::signal::ctrl_c() => {
                    stdout.write_all(b"\r\n").await?;
                    stdout.flush().await?;
                }
            }
        }
        disable_raw_mode()?;

        Ok(signal)
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

        self.input.clear();
        self.input.extend_from_slice(command.as_bytes());
        self.input_cursor = self.input.len();
        sink.write_all(b"\r\x1b[K").await?;
        if let Some(prompt) = &self.prompt {
            prompt.draw(&mut *sink).await?;
        }
        sink.write_all(command.as_bytes()).await?;

        Ok(())
    }

    async fn handle_autocomplete<S: AsyncWrite + Unpin>(
        &mut self,
        autocomplete_options: &mut Vec<String>,
        autocomplete_cursor: &mut isize,
        stdout: &mut S,
    ) -> io::Result<()> {
        let command_str = std::str::from_utf8(&self.input)
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
            if let Some(prompt) = &self.prompt {
                prompt.draw(&mut *stdout).await?;
            }
            stdout.write_all(suffix.as_bytes()).await?;
            stdout.write_u8(b' ').await?;

            self.input.clear();
            self.input.extend(suffix.as_bytes());
            self.input.push(b' ');

            *autocomplete_cursor -= 1;
            self.input_cursor = suffix.len() + 1;
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
            self.input.push(c as u8);
        }
        self.input.push(b' ');

        *autocomplete_options = suggestions;
        *autocomplete_cursor = autocomplete_options.len() as isize - 1;
        self.input_cursor += suffix.len() + 1;

        Ok(())
    }

    async fn move_cursor_word_left<S: AsyncWrite + Unpin>(
        &mut self,
        sink: &mut S,
    ) -> io::Result<()> {
        let mut temp_buf = vec![];
        if let Some(pos) = self.input[..self.input_cursor - 1]
            .iter()
            .rposition(|c| *c == b' ')
        {
            execute!(
                temp_buf,
                MoveLeft(self.input_cursor as u16 - pos as u16 - 1)
            )?;
            self.input_cursor = pos + 1;
        } else {
            execute!(temp_buf, MoveLeft(self.input_cursor as u16))?;
            self.input_cursor = 0;
        }
        sink.write_all(&temp_buf).await?;
        Ok(())
    }

    async fn move_cursor_word_right<S: AsyncWrite + Unpin>(
        &mut self,
        sink: &mut S,
    ) -> io::Result<()> {
        let mut temp_buf = vec![];
        if let Some(pos) = self.input[self.input_cursor + 1..]
            .iter()
            .position(|c| *c == b' ')
        {
            execute!(temp_buf, MoveRight(pos as u16 + 1))?;
            self.input_cursor = pos + self.input_cursor + 1;
        } else {
            execute!(
                temp_buf,
                MoveRight(self.input.len() as u16 - self.input_cursor as u16)
            )?;
            self.input_cursor = self.input.len();
        }
        sink.write_all(&temp_buf).await?;
        Ok(())
    }

    async fn handle_right_arrow<S: AsyncWrite + Unpin>(&mut self, s: &mut S) -> io::Result<()> {
        s.write_all(&[ARROW_ANCHOR, RIGHT_ARROW[0], RIGHT_ARROW[1]])
            .await?;
        self.input_cursor += 1;

        Ok(())
    }

    async fn handle_left_arrow<S: AsyncWrite + Unpin>(&mut self, s: &mut S) -> io::Result<()> {
        s.write_all(&[ARROW_ANCHOR, LEFT_ARROW[0], LEFT_ARROW[1]])
            .await?;
        self.input_cursor -= 1;

        Ok(())
    }

    async fn handle_ctrl_c<S: AsyncWrite + Unpin>(&mut self, s: &mut S) -> io::Result<()> {
        self.input.clear();
        self.input_cursor = 0;
        self.history_cursor = None;
        s.write_all(b"\r\n").await?;
        s.flush().await?;

        Ok(())
    }

    fn handle_ctrl_d(&mut self) {
        self.input.clear();
        self.history_cursor = None;
    }

    async fn handle_backspace<S: AsyncWrite + Unpin>(&mut self, s: &mut S) -> io::Result<()> {
        self.history_cursor = None;
        if self.input_cursor != 0 {
            self.input_cursor -= 1;
            self.input.remove(self.input_cursor);
            if self.input_cursor == self.input.len() {
                s.write_all(b"\x08 \x08").await?;
            } else {
                let mut temp_buf = vec![];
                execute!(temp_buf, Clear(ClearType::CurrentLine))?;
                s.write_all(&temp_buf).await?;
                s.write_all(b"\r").await?;
                if let Some(prompt) = &self.prompt {
                    prompt.draw(&mut *s).await?;
                }
                s.write_all(&self.input).await?;
                temp_buf.clear();
                execute!(
                    temp_buf,
                    MoveLeft((self.input.len() - self.input_cursor) as u16)
                )?;
                s.write_all(&temp_buf).await?;
                s.flush().await?;
            }
        }

        Ok(())
    }

    async fn handle_char<S: AsyncWrite + Unpin>(&mut self, s: &mut S, byte: u8) -> io::Result<()> {
        if !self.input.is_empty() && self.input_cursor != self.input.len() {
            self.input.insert(self.input_cursor, byte);
            let mut temp_buf = vec![];
            execute!(temp_buf, Clear(ClearType::CurrentLine))?;
            s.write_all(&temp_buf).await?;
            s.write_all(b"\r").await?;
            if let Some(prompt) = &self.prompt {
                prompt.draw(&mut *s).await?;
            }
            s.write_all(&self.input).await?;
            temp_buf.clear();
            execute!(
                temp_buf,
                MoveLeft((self.input.len() - self.input_cursor - 1) as u16)
            )?;
            s.write_all(&temp_buf).await?;
            s.flush().await?;
        } else {
            self.input.push(byte);
            s.write_all(&[byte]).await?;
        }
        self.input_cursor += 1;
        self.history_cursor = None;
        // [TODO]
        // autocomplete_cursor = 0;
        // curr_autocomplete_options.clear();

        Ok(())
    }

    async fn handle_arrows<S: AsyncWrite + Unpin, I: AsyncRead + Unpin>(
        &mut self,
        s: &mut S,
        i: &mut I,
        arrow_buffer: &mut [u8; 2],
    ) -> io::Result<()> {
        if i.read_exact(arrow_buffer.as_mut_slice()).await.is_ok() {
            match *arrow_buffer {
                UP_ARROW => {
                    self.handle_history_change(HistoryDirection::Up, s).await?;
                }
                DOWN_ARROW => {
                    self.handle_history_change(HistoryDirection::Down, s)
                        .await?;
                }
                RIGHT_ARROW if self.input_cursor < self.input.len() => {
                    self.handle_right_arrow(s).await?;
                }
                LEFT_ARROW if self.input_cursor != 0 => {
                    self.handle_left_arrow(s).await?;
                }
                // TODO: check the rest, mb this is the place where we should handle deleting of
                // word
                _ => {}
            }
        }
        Ok(())
    }

    pub(crate) async fn dump_history<S: AsyncWrite + Unpin>(
        &mut self,
        sink: &mut S,
    ) -> io::Result<()> {
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
}

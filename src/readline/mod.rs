use crate::{
    autocomplete::Trie,
    prompt::{DefaultPrompt, Prompt},
    readline::constants::{
        BACKSPACE, CTRL_C, CTRL_D, CTRL_LEFT_ARROW, CTRL_RIGHT_ARROW, ESC, HISTORY_FILE,
        LEFT_ARROW, RIGHT_ARROW, SHOULD_NOT_REDRAW_PROMPT,
    },
};

#[derive(Debug)]
pub enum HistoryDirection {
    Up,
    Down,
}

use constants::{
    DECSM, DOWN_ARROW, KEY_TIMEOUT_DURATION, NEWLINE, OPTION_KEY, RETURN, TAB, UP_ARROW,
};
use crossterm::{
    cursor::{MoveLeft, MoveRight},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, Clear, ClearType},
};
use std::collections::VecDeque;
use tokio::{
    io::{self, AsyncReadExt, AsyncWrite, AsyncWriteExt, Stdin, Stdout},
    time::timeout,
};

use vim::{
    Modifier, VimCommand, VimMode, VimVerb, ENTER_INSERT_LINE_END, ENTER_INSERT_LINE_START,
    ENTER_INSERT_NEXT_CHAR, VIM_DELIMITERS, VIM_ENTER_INSERT_MODE_STROKES,
};

pub mod constants;
pub mod signal;
pub mod vim;

use signal::Signal;

#[derive(Debug)]
pub struct Readline<P> {
    /// Instance of trait [`Prompt`], contains method [`Prompt::draw`] which is used in couple of
    /// places to redraw prompt as needed.
    pub prompt: Option<P>,

    /// Internal buffer for storing intermidiate input of user.
    buffer: Vec<u8>,

    /// Field to store current state of the cursor
    input_cursor: usize,

    /// Stores shell history, at runtime is populated automatically as needed. When [`Readline`] is
    /// instansiated history is constructed from file.
    pub history: VecDeque<String>,

    /// Field to store index of current active history item
    history_cursor: Option<usize>,

    /// Custom trie implementation to handle populating and suggesting autocomplete options.
    pub autocomplete_options: Trie,

    curr_autocomplete_options: Vec<String>,

    /// Field to store index of currently selected autocomplete option.
    autocomplete_cursor: isize,
    pub last_pressed: Option<u8>,
    ctrl_arrow_buffer: [u8; 2],

    pub vim_mode_enabled: bool,
    vim_mode: VimMode,

    stdin: Stdin,
    stdout: Stdout,
}

impl Readline<DefaultPrompt> {
    pub async fn new() -> Readline<DefaultPrompt> {
        let history = tokio::fs::read_to_string(HISTORY_FILE)
            .await
            .unwrap_or(String::new());

        Readline {
            buffer: vec![],
            input_cursor: 0,
            history: history.lines().map(|l| l.to_string()).collect(),
            history_cursor: None,
            autocomplete_options: Trie::new(),
            last_pressed: None,
            prompt: None,
            curr_autocomplete_options: vec![],
            autocomplete_cursor: 0,
            ctrl_arrow_buffer: [0u8; 2],
            stdin: io::stdin(),
            stdout: io::stdout(),
            vim_mode_enabled: true,
            vim_mode: VimMode::Insert,
        }
    }
}

impl<P: Prompt> Readline<P> {
    pub async fn new_with_prompt(prompt: P) -> Readline<P> {
        let history = tokio::fs::read_to_string(HISTORY_FILE)
            .await
            .unwrap_or(String::new());

        Readline::<P> {
            buffer: vec![],
            input_cursor: 0,
            history: history.lines().map(|l| l.to_string()).collect(),
            history_cursor: None,
            autocomplete_options: Trie::new(),
            last_pressed: None,
            prompt: Some(prompt),
            curr_autocomplete_options: vec![],
            autocomplete_cursor: 0,
            ctrl_arrow_buffer: [0u8; 2],
            stdin: io::stdin(),
            stdout: io::stdout(),
            vim_mode_enabled: true,
            vim_mode: VimMode::Insert,
        }
    }

    pub async fn read(&mut self, input: &mut String) -> io::Result<Signal> {
        enable_raw_mode()?;
        let signal;

        loop {
            if let Some(prompt) = &self.prompt {
                if self.buffer.is_empty()
                    && !SHOULD_NOT_REDRAW_PROMPT.contains(&self.last_pressed.unwrap_or(0))
                {
                    prompt.draw(&mut self.stdout).await?;
                }
            }

            match self.handle_input_event(input).await? {
                Some(s) => {
                    signal = s;
                    break;
                }
                None => continue,
            }
        }
        disable_raw_mode()?;

        Ok(signal)
    }

    async fn handle_input_event(&mut self, input: &mut String) -> io::Result<Option<Signal>> {
        match (self.vim_mode_enabled, self.vim_mode) {
            (true, VimMode::Normal) => self.handle_input_event_vim_normal(input).await,
            (false, _) | (true, VimMode::Insert) => self.handle_input_event_default(input).await,
        }
    }

    async fn handle_input_event_default(
        &mut self,
        input: &mut String,
    ) -> io::Result<Option<Signal>> {
        if let Ok(byte) = self.stdin.read_u8().await {
            self.last_pressed = Some(byte);
            match byte {
                RETURN | NEWLINE => {
                    self.handle_newline(input).await?;
                    return Ok(Some(Signal::Success));
                }
                CTRL_C => {
                    self.handle_ctrl_c().await?;
                }
                CTRL_D => {
                    self.handle_exit();
                    return Ok(Some(Signal::CtrlD));
                }
                BACKSPACE => {
                    self.handle_backspace().await?;
                }
                ESC => {
                    self.handle_escape_sequence().await?;
                }
                OPTION_KEY => {
                    self.handle_option_key(byte).await?;
                }
                TAB => {
                    self.handle_autocomplete().await?;
                }
                _ => {
                    self.handle_char(byte).await?;
                }
            }
        }

        Ok(None)
    }

    async fn handle_input_event_vim_normal(
        &mut self,
        input: &mut String,
    ) -> io::Result<Option<Signal>> {
        let Some(command) = VimCommand::read(&mut self.stdin).await? else {
            return Ok(None);
        };

        let count = if let Some(Modifier::Count(count)) = command.modifier {
            count
        } else {
            1
        };

        for _ in 0..count {
            match (command.verb, command.modifier, command.motion) {
                (None, _, vim::Motion::Left) => self.handle_left_arrow().await?,
                (None, _, vim::Motion::Right) => self.handle_right_arrow().await?,
                (None, _, vim::Motion::Up) => {
                    self.handle_history_change(HistoryDirection::Up).await?
                }
                (None, _, vim::Motion::Down) => {
                    self.handle_history_change(HistoryDirection::Down).await?
                }
                (None, _, vim::Motion::LineStart) => self.move_cursor_to_line_start().await?,
                (None, _, vim::Motion::LineEnd) => self.move_cursor_to_line_end().await?,
                (None, _, vim::Motion::ToNextChar(c)) => self.move_cursor_to_next_char(c).await?,
                (None, _, vim::Motion::ToPrevChar(c)) => self.move_cursor_to_prev_char(c).await?,
                (None, _, vim::Motion::BeforeNextChar(c)) => {
                    self.move_cursor_to_next_char(c).await?
                }
                (None, _, vim::Motion::BeforePrevChar(c)) => {
                    self.move_cursor_to_prev_char(c).await?
                }
                (None, _, vim::Motion::NextWord) => self.move_cursor_word_right().await?,
                (None, _, vim::Motion::PrevWord) => self.move_cursor_word_left().await?,
                (None, _, vim::Motion::EndOfWord) => self.move_cursor_word_right().await?, // For now
                // the same as `w`, handle it separately in the future.
                (None, None, vim::Motion::TextObject(s))
                    if VIM_ENTER_INSERT_MODE_STROKES.contains(&s) =>
                {
                    self.vim_mode = VimMode::Insert;

                    match s {
                        ENTER_INSERT_NEXT_CHAR => {
                            self.handle_right_arrow().await?;
                        }
                        ENTER_INSERT_LINE_END => {
                            self.move_cursor_to_line_end().await?;
                        }
                        ENTER_INSERT_LINE_START => {
                            self.move_cursor_to_line_start().await?;
                        }
                        _ => unreachable!(),
                    }
                }
                (None, None, vim::Motion::TextObject(s))
                    if s == RETURN as char || s == NEWLINE as char =>
                {
                    self.handle_newline(input).await?;
                    self.vim_mode = VimMode::Insert;
                    self.last_pressed = Some(b'\r');
                    return Ok(Some(Signal::Success));
                }
                (None, None, vim::Motion::TextObject(s)) if s == CTRL_D as char => {
                    self.handle_exit();
                    return Ok(Some(Signal::CtrlD));
                }
                (None, None, vim::Motion::TextObject(s)) if s == CTRL_C as char => {
                    self.handle_ctrl_c().await?;
                    self.last_pressed = Some(CTRL_C);
                    return Ok(Some(Signal::CtrlC));
                }
                (None, None, vim::Motion::TextObject(_)) => {}
                (Some(_), None, vim::Motion::Left) => todo!(),
                (Some(_), None, vim::Motion::Right) => todo!(),
                (Some(_), None, vim::Motion::Up) => todo!(),
                (Some(_), None, vim::Motion::Down) => todo!(),
                (Some(_), None, vim::Motion::LineStart) => todo!(),
                (Some(_), None, vim::Motion::LineEnd) => todo!(),
                (Some(_), None, vim::Motion::ToNextChar(_)) => todo!(),
                (Some(_), None, vim::Motion::ToPrevChar(_)) => todo!(),
                (Some(_), None, vim::Motion::BeforeNextChar(_)) => todo!(),
                (Some(_), None, vim::Motion::BeforePrevChar(_)) => todo!(),
                (Some(VimVerb::Delete | VimVerb::Change), None, vim::Motion::NextWord) => {
                    self.delete_next_word().await?
                }
                (Some(VimVerb::Delete | VimVerb::Change), None, vim::Motion::PrevWord) => {
                    self.delete_prev_word().await?
                }
                (Some(_), None, vim::Motion::EndOfWord) => todo!(),
                (Some(_), None, vim::Motion::TextObject(_)) => todo!(),
                (Some(_), Some(_), vim::Motion::Left) => todo!(),
                (Some(_), Some(_), vim::Motion::Right) => todo!(),
                (Some(_), Some(_), vim::Motion::Up) => todo!(),
                (Some(_), Some(_), vim::Motion::Down) => todo!(),
                (Some(_), Some(_), vim::Motion::LineStart) => todo!(),
                (Some(_), Some(_), vim::Motion::LineEnd) => todo!(),
                (Some(_), Some(_), vim::Motion::ToNextChar(_)) => todo!(),
                (Some(_), Some(_), vim::Motion::ToPrevChar(_)) => todo!(),
                (Some(_), Some(_), vim::Motion::BeforeNextChar(_)) => todo!(),
                (Some(_), Some(_), vim::Motion::BeforePrevChar(_)) => todo!(),
                (Some(_), Some(_), vim::Motion::NextWord) => todo!(),
                (Some(_), Some(_), vim::Motion::PrevWord) => todo!(),
                (Some(_), Some(_), vim::Motion::EndOfWord) => todo!(),
                (
                    Some(VimVerb::Delete | VimVerb::Change),
                    Some(Modifier::Around),
                    vim::Motion::TextObject(c),
                ) if VIM_DELIMITERS.contains(&c) => self.delete_around(c).await?,
                _ => {}
            }
        }

        if command.verb == Some(VimVerb::Change) {
            self.vim_mode = VimMode::Insert;
        }

        Ok(None)
    }

    async fn handle_newline(&mut self, input: &mut String) -> io::Result<()> {
        self.history_cursor = None;
        self.stdout.write_all(b"\r\n").await?;
        self.stdout.flush().await?;

        if !self.buffer.is_empty() {
            let p = &self.buffer.clone();
            let command_str = String::from_utf8_lossy(p);
            if self.history_cursor.is_none() {
                self.history.push_front(command_str.to_string());
            }
            *input = command_str.to_string();
        }
        self.buffer.clear();
        self.input_cursor = 0;

        Ok(())
    }

    async fn handle_history_change(&mut self, to: HistoryDirection) -> io::Result<()> {
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

        self.buffer.clear();
        self.buffer.extend_from_slice(command.as_bytes());
        self.input_cursor = self.buffer.len();
        self.stdout.write_all(b"\r\x1b[K").await?;
        if let Some(prompt) = &self.prompt {
            prompt.draw(&mut self.stdout).await?;
        }
        self.stdout.write_all(command.as_bytes()).await?;
        self.stdout.flush().await?;

        Ok(())
    }

    async fn handle_option_key(&mut self, byte: u8) -> io::Result<()> {
        let read_result = timeout(
            KEY_TIMEOUT_DURATION,
            self.stdin.read_exact(&mut self.ctrl_arrow_buffer),
        )
        .await;
        if read_result.is_ok() {
            match self.ctrl_arrow_buffer {
                CTRL_LEFT_ARROW => {
                    self.move_cursor_word_left().await?;
                }
                CTRL_RIGHT_ARROW => {
                    self.move_cursor_word_right().await?;
                }
                _ => {}
            }
        } else {
            self.handle_char(byte).await?;
        }

        Ok(())
    }

    async fn handle_autocomplete(&mut self) -> io::Result<()> {
        let command_str = std::str::from_utf8(&self.buffer)
            .map_err(|_| io::Error::other("Input is not valid utf-8"))?;

        if !self.curr_autocomplete_options.is_empty() {
            if self.autocomplete_cursor < 0 {
                self.autocomplete_cursor = self.curr_autocomplete_options.len() as isize - 1;
            }
            let Some(suffix) = self
                .curr_autocomplete_options
                .get(self.autocomplete_cursor as usize)
                .map(|o| o.to_string())
            else {
                return Ok(());
            };

            self.stdout.write_all(b"\r\x1b[K").await?;
            if let Some(prompt) = &self.prompt {
                prompt.draw(&mut self.stdout).await?;
            }
            self.stdout.write_all(suffix.as_bytes()).await?;
            self.stdout.write_u8(b' ').await?;
            self.stdout.flush().await?;

            self.buffer.clear();
            self.buffer.extend(suffix.as_bytes());
            self.buffer.push(b' ');

            self.autocomplete_cursor -= 1;
            self.input_cursor = suffix.len() + 1;
            return Ok(());
        }

        let suggestions = self.autocomplete_options.suggest(command_str);
        if suggestions.is_empty() {
            return Ok(());
        }

        let suffix = &suggestions[0].clone()[command_str.len()..];
        self.stdout.write_all(suffix.as_bytes()).await?;
        self.stdout.write_u8(b' ').await?;
        self.stdout.flush().await?;

        self.buffer.extend_from_slice(suffix.as_bytes());
        self.buffer.push(b' ');

        self.curr_autocomplete_options = suggestions;
        self.autocomplete_cursor = self.curr_autocomplete_options.len() as isize - 1;
        self.input_cursor += suffix.len() + 1;

        Ok(())
    }

    async fn move_cursor_left_to_char(&mut self, c: char) -> io::Result<()> {
        if self.input_cursor == 0 {
            return Ok(());
        }
        let mut temp_buf = vec![];
        if let Some(pos) = self.buffer[..self.input_cursor - 1]
            .iter()
            .rposition(|i| *i == c as u8)
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
        self.stdout.write_all(&temp_buf).await?;
        self.stdout.flush().await?;
        Ok(())
    }

    async fn move_cursor_right_to_char(&mut self, c: char) -> io::Result<()> {
        if self.input_cursor >= self.buffer.len() {
            return Ok(());
        }

        let mut temp_buf = vec![];
        if let Some(pos) = self.buffer[self.input_cursor + 1..]
            .iter()
            .position(|i| *i == c as u8)
        {
            execute!(temp_buf, MoveRight(pos as u16 + 1))?;
            self.input_cursor = pos + self.input_cursor + 1;
        } else {
            execute!(
                temp_buf,
                MoveRight(self.buffer.len() as u16 - self.input_cursor as u16)
            )?;
            self.input_cursor = self.buffer.len();
        }
        self.stdout.write_all(&temp_buf).await?;
        self.stdout.flush().await?;
        Ok(())
    }

    async fn move_cursor_word_left(&mut self) -> io::Result<()> {
        self.move_cursor_left_to_char(' ').await
    }

    async fn move_cursor_word_right(&mut self) -> io::Result<()> {
        self.move_cursor_right_to_char(' ').await
    }

    async fn handle_right_arrow(&mut self) -> io::Result<()> {
        if self.input_cursor < self.buffer.len() {
            self.stdout.write_all(&[ESC, 91, 67]).await?;
            self.stdout.flush().await?;
            self.input_cursor += 1;
        }

        Ok(())
    }

    async fn handle_left_arrow(&mut self) -> io::Result<()> {
        if self.input_cursor != 0 {
            self.stdout.write_all(&[ESC, 91, 68]).await?;
            self.stdout.flush().await?;
            self.input_cursor -= 1;
        }

        Ok(())
    }

    async fn handle_ctrl_c(&mut self) -> io::Result<()> {
        self.buffer.clear();
        self.input_cursor = 0;
        self.history_cursor = None;
        self.stdout.write_all(b"\r\n").await?;
        self.stdout.flush().await?;

        Ok(())
    }

    fn handle_exit(&mut self) {
        self.buffer.clear();
        self.history_cursor = None;
    }

    async fn handle_backspace(&mut self) -> io::Result<()> {
        self.history_cursor = None;
        if self.input_cursor != 0 {
            self.input_cursor -= 1;
            self.buffer.remove(self.input_cursor);
            if self.input_cursor == self.buffer.len() {
                self.stdout.write_all(b"\x08 \x08").await?;
            } else {
                let mut temp_buf = vec![];
                execute!(temp_buf, Clear(ClearType::CurrentLine))?;
                self.stdout.write_all(&temp_buf).await?;
                self.stdout.write_all(b"\r").await?;
                if let Some(prompt) = &self.prompt {
                    prompt.draw(&mut self.stdout).await?;
                }
                self.stdout.write_all(&self.buffer).await?;
                temp_buf.clear();
                execute!(
                    temp_buf,
                    MoveLeft((self.buffer.len() - self.input_cursor) as u16)
                )?;
                self.stdout.write_all(&temp_buf).await?;
            }
        }
        self.stdout.flush().await?;

        Ok(())
    }

    async fn handle_char_vim_normal_mode(&mut self, byte: u8) -> io::Result<()> {
        // if VIM_ENTER_INSERT_MODE_STROKES.contains(&byte) {
        //     self.vim_mode = VimMode::Insert;
        // }
        //
        // match byte {
        //     ENTER_INSERT_NEXT_CHAR | b'l' => {
        //         self.handle_right_arrow().await?;
        //     }
        //     ENTER_INSERT_LINE_END | b'$' => {
        //         self.move_cursor_to_line_end().await?;
        //     }
        //     ENTER_INSERT_LINE_START | b'0' => {
        //         self.move_cursor_to_line_start().await?;
        //     }
        //     // TODO handle `e` independentally
        //     NEXT_WORD | b'e' => {
        //         self.move_cursor_word_right().await?;
        //     }
        //     PREV_WORD => {
        //         self.move_cursor_word_left().await?;
        //     }
        //     b'h' => {
        //         self.handle_left_arrow().await?;
        //     }
        //     b'k' => {
        //         self.handle_history_change(HistoryDirection::Up).await?;
        //     }
        //     b'j' => {
        //         self.handle_history_change(HistoryDirection::Up).await?;
        //     }
        //
        //     _ => {}
        // }
        // Ok(())
        todo!()
    }

    async fn handle_char(&mut self, byte: u8) -> io::Result<()> {
        if self.vim_mode_enabled && self.vim_mode == VimMode::Normal {
            return self.handle_char_vim_normal_mode(byte).await;
        }

        if !self.buffer.is_empty() && self.input_cursor != self.buffer.len() {
            self.buffer.insert(self.input_cursor, byte);
            let mut temp_buf = vec![];
            execute!(temp_buf, Clear(ClearType::CurrentLine))?;
            self.stdout.write_all(&temp_buf).await?;
            self.stdout.write_all(b"\r").await?;
            if let Some(prompt) = &self.prompt {
                prompt.draw(&mut self.stdout).await?;
            }
            self.stdout.write_all(&self.buffer).await?;
            temp_buf.clear();
            execute!(
                temp_buf,
                MoveLeft((self.buffer.len() - self.input_cursor - 1) as u16)
            )?;
            self.stdout.write_all(&temp_buf).await?;
        } else {
            self.buffer.push(byte);
            self.stdout.write_all(&[byte]).await?;
        }
        self.stdout.flush().await?;
        self.input_cursor += 1;
        self.history_cursor = None;
        self.autocomplete_cursor = 0;
        self.curr_autocomplete_options.clear();

        Ok(())
    }

    async fn handle_escape_sequence(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 1];

        let read_result = timeout(KEY_TIMEOUT_DURATION, self.stdin.read_exact(&mut buf)).await;

        match read_result {
            Ok(Ok(_)) => match buf[0] {
                DECSM => {
                    let mut arrow_code = [0u8; 1];
                    if self.stdin.read_exact(&mut arrow_code).await.is_ok() {
                        match arrow_code[0] {
                            UP_ARROW => self.handle_history_change(HistoryDirection::Up).await?,
                            DOWN_ARROW => {
                                self.handle_history_change(HistoryDirection::Down).await?
                            }
                            RIGHT_ARROW => self.handle_right_arrow().await?,
                            LEFT_ARROW => self.handle_left_arrow().await?,
                            _ => {}
                        }
                    }
                }
                BACKSPACE | 0x08 => {
                    self.delete_prev_word().await?;
                }
                other => {
                    unimplemented!("pressed {}", other);
                }
            },
            Err(_) => {
                // single ESC
                if self.vim_mode_enabled && self.vim_mode == VimMode::Insert {
                    self.vim_mode = VimMode::Normal;
                    self.handle_left_arrow().await?;
                }
            }
            Ok(Err(_)) => {}
        }

        Ok(())
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

    async fn delete_prev_word(&mut self) -> io::Result<()> {
        if self.input_cursor == 0 {
            return Ok(());
        };

        let prev_space = self
            .buffer
            .get(..self.input_cursor - 1)
            .and_then(|i| i.iter().rposition(|c| *c == b' '))
            .unwrap_or(0);
        let mut temp_buf = vec![];
        execute!(temp_buf, Clear(ClearType::CurrentLine))?;
        self.stdout.write_all(&temp_buf).await?;
        self.stdout.write_all(b"\r").await?;
        if let Some(prompt) = &self.prompt {
            prompt.draw(&mut self.stdout).await?;
        }
        let from = if prev_space == 0 { 0 } else { prev_space + 1 };
        let deleted = self.buffer.drain(from..self.input_cursor).len();
        self.input_cursor -= deleted;
        self.stdout.write_all(&self.buffer).await?;
        if self.input_cursor != self.buffer.len() {
            temp_buf.clear();
            execute!(
                temp_buf,
                MoveLeft((self.buffer.len() - self.input_cursor) as u16)
            )?;
            self.stdout.write_all(&temp_buf).await?;
        }
        self.stdout.flush().await?;
        Ok(())
    }

    async fn delete_next_word(&mut self) -> io::Result<()> {
        if self.input_cursor >= self.buffer.len() {
            return Ok(());
        }

        let next_space = self
            .buffer
            .get(self.input_cursor + 1..)
            .and_then(|i| i.iter().position(|c| *c == b' '))
            .unwrap_or(0);
        let mut temp_buf = vec![];
        execute!(temp_buf, Clear(ClearType::CurrentLine))?;
        self.stdout.write_all(&temp_buf).await?;
        self.stdout.write_all(b"\r").await?;
        if let Some(prompt) = &self.prompt {
            prompt.draw(&mut self.stdout).await?;
        }
        let to = if next_space == 0 {
            self.buffer.len()
        } else {
            next_space + 1 + self.input_cursor
        };
        self.buffer.drain(self.input_cursor..to);
        self.stdout.write_all(&self.buffer).await?;
        if self.input_cursor != self.buffer.len() {
            temp_buf.clear();
            execute!(
                temp_buf,
                MoveLeft((self.buffer.len() - self.input_cursor) as u16)
            )?;
            self.stdout.write_all(&temp_buf).await?;
        }
        self.stdout.flush().await?;
        Ok(())
    }

    async fn move_cursor_to_line_end(&mut self) -> io::Result<()> {
        let mut temp_buf = vec![];
        execute!(
            temp_buf,
            MoveRight((self.buffer.len() - self.input_cursor) as u16)
        )?;
        self.stdout.write_all(&temp_buf).await?;
        self.input_cursor = self.buffer.len();
        self.stdout.flush().await?;
        Ok(())
    }

    async fn move_cursor_to_line_start(&mut self) -> io::Result<()> {
        let mut temp_buf = vec![];
        execute!(temp_buf, MoveLeft(self.input_cursor as u16))?;
        self.stdout.write_all(&temp_buf).await?;
        self.input_cursor = 0;
        self.stdout.flush().await?;
        Ok(())
    }

    async fn move_cursor_to_next_char(&mut self, c: char) -> io::Result<()> {
        self.move_cursor_right_to_char(c).await
    }

    async fn move_cursor_to_prev_char(&mut self, c: char) -> io::Result<()> {
        self.move_cursor_left_to_char(c).await
    }

    async fn delete_around(&mut self, del: char) -> io::Result<()> {
        todo!()
    }
}

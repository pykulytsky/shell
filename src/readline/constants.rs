#![allow(dead_code)]

use std::time::Duration;

pub const DOUBLE_QUOTES_ESCAPE: &[char] = &['$', '\\', '"'];

pub const REDIRECTS: &[&str] = &[">", "1>", "2>", ">>", "1>>", "2>>"];

pub const PIPE: &str = "|";

pub const CTRL_C: u8 = 3;
pub const CTRL_D: u8 = 4;
pub const CTRL_Z: u8 = 26;
pub const BACKSPACE: u8 = 127;
pub const CTRL: u8 = 17;
pub const ESC: u8 = 27;
pub const OPTION_KEY: u8 = b';';
pub const TAB: u8 = b'\t';
pub const NEWLINE: u8 = b'\n';
pub const RETURN: u8 = b'\r';

pub const UP_ARROW: u8 = b'A';
pub const DOWN_ARROW: u8 = b'B';
pub const RIGHT_ARROW: u8 = b'C';
pub const LEFT_ARROW: u8 = b'D';
pub const CTRL_LEFT_ARROW: [u8; 2] = [51, 68];
pub const CTRL_RIGHT_ARROW: [u8; 2] = [51, 67];
pub const DECSM: u8 = b'[';

pub const SHOULD_NOT_REDRAW_PROMPT: &[u8] = &[BACKSPACE, ESC, CTRL_Z];

pub const BUILTINS: &[&str] = &["cd", "exit", "echo", "type", "pwd", "history"];

pub const HISTORY_FILE: &str = "shell_history";

pub const GLOB: &[char] = &['*', '?', '[', ']', '{', '}'];

pub const KEY_TIMEOUT_DURATION: Duration = Duration::from_millis(10);

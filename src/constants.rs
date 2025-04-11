#![allow(dead_code)]

pub const DOUBLE_QUOTES_ESCAPE: &[char] = &['$', '\\', '"'];

pub const REDIRECTS: &[&str] = &[">", "1>", "2>", ">>", "1>>", "2>>"];

pub const PIPE: &str = "|";

pub const CTRL_C: u8 = 3;
pub const CTRL_D: u8 = 4;
pub const BACKSPACE: u8 = 127;
pub const CTRL: u8 = 17;
pub const ESC: u8 = 27;

pub const ARROW_ANCHOR: u8 = 27;
pub const UP_ARROW: [u8; 2] = [91, 65];
pub const DOWN_ARROW: [u8; 2] = [91, 66];
pub const RIGHT_ARROW: [u8; 2] = [91, 67];
pub const LEFT_ARROW: [u8; 2] = [91, 68];
pub const CTRL_LEFT_ARROW: [u8; 2] = [51, 68];
pub const CTRL_RIGHT_ARROW: [u8; 2] = [51, 67];


pub const SHOULD_NOT_REDRAW_PROMPT: &[u8] = &[BACKSPACE, ARROW_ANCHOR];

pub const BUILTINS: &[&str] = &["cd", "exit", "echo", "type", "pwd", "history"];

pub const HISTORY_FILE: &str = "shell_history";

#![allow(dead_code)]

pub const DOUBLE_QUOTES_ESCAPE: &[char] = &['$', '\\', '"'];

pub const REDIRECTS: &[&str] = &[">", "1>", "2>", ">>", "1>>", "2>>"];

pub const CTRL_C: u8 = 3;
pub const CTRL_D: u8 = 4;
pub const BACKSPACE: u8 = 127;

pub const ARROW_ANCHOR: u8 = 27;
pub const UP_ARROW: [u8; 2] = [91, 65];
pub const DOWN_ARROW: [u8; 2] = [91, 66];
pub const RIGHT_ARROW: [u8; 2] = [91, 67];
pub const LEFT_ARROW: [u8; 2] = [91, 68];

pub const SHOULD_NOT_REDRAW_PROMPT: &[u8] = &[BACKSPACE, ARROW_ANCHOR];

pub const BUILTINS: &[&str] = &["cd", "exit", "echo", "type", "pwd", "history"];

/// Normalizes output from external command, by including `\r` before each `\n`
pub fn normalize_output(input: Vec<u8>) -> Vec<u8> {
    input
        .iter()
        .flat_map(|&b| {
            if b == b'\n' {
                vec![b'\r', b'\n']
            } else {
                vec![b]
            }
        })
        .collect::<Vec<_>>()
}

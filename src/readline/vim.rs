#[derive(Debug, PartialEq)]
pub enum VimMode {
    Normal,
    Insert,
}

pub const VIM_ENTER_INSERT: u8 = b'i';
pub const VIM_ENTER_INSERT_LINE_START: u8 = b'I';
pub const VIM_ENTER_INSERT_NEXT_CHAR: u8 = b'a';
pub const VIM_ENTER_INSERT_LINE_END: u8 = b'A';

pub const NEXT_WORD: u8 = b'w';
pub const PREV_WORD: u8 = b'b';

#[allow(clippy::byte_char_slices)]
pub const VIM_ENTER_INSERT_MODE_STROKES: &[u8] = &[
    VIM_ENTER_INSERT,
    VIM_ENTER_INSERT_LINE_START,
    VIM_ENTER_INSERT_NEXT_CHAR,
    VIM_ENTER_INSERT_LINE_END,
];

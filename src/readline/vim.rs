use tokio::io::{self, AsyncRead, AsyncReadExt};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum VimMode {
    Normal,
    Insert,
}

pub const VIM_ENTER_INSERT: char = 'i';
pub const ENTER_INSERT_LINE_START: char = 'I';
pub const ENTER_INSERT_NEXT_CHAR: char = 'a';
pub const ENTER_INSERT_LINE_END: char = 'A';

pub const NEXT_WORD: u8 = b'w';
pub const PREV_WORD: u8 = b'b';

#[allow(clippy::byte_char_slices)]
pub const VERBS: &[u8] = &[b'd', b'c', b'y'];

#[allow(clippy::byte_char_slices)]
pub const MODIFIERS: &[u8] = &[b'i', b'a'];

#[allow(clippy::byte_char_slices)]
pub const VIM_ENTER_INSERT_MODE_STROKES: &[char] = &[
    VIM_ENTER_INSERT,
    ENTER_INSERT_LINE_START,
    ENTER_INSERT_NEXT_CHAR,
    ENTER_INSERT_LINE_END,
];

pub const VERB_DELETE: u8 = b'd';
pub const VERB_CHANGE: u8 = b'c';
pub const VERB_YANK: u8 = b'y';
pub const VIM_DELIMITERS: &[char] = &['(', ')', '{', '}', '<', '>'];

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum VimVerb {
    Change,
    Delete,
    /// yank (copy)
    Yank,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Modifier {
    /// When you press for example <2>dd to delete two lines in a row
    Count(u16),
    Inner,
    Around,
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Motion {
    Left,
    Right,
    Up,
    Down,
    LineStart, // TODO: fix reading `0`, as for now i presume it is handled as ascii digit and
    // counted as modifier
    LineEnd,
    ToNextChar(char),
    ToPrevChar(char),
    BeforeNextChar(char),
    BeforePrevChar(char),
    NextWord,
    PrevWord,
    EndOfWord,
    /// Represents text object witch is used in conjunction with `i` or `a` modifiers.
    TextObject(char),
}

#[derive(Debug, PartialEq)]
pub struct VimCommand {
    pub verb: Option<VimVerb>,
    pub modifier: Option<Modifier>,
    pub motion: Motion,
}

impl VimCommand {
    pub async fn read<S: AsyncRead + Unpin>(stdin: &mut S) -> io::Result<Option<Self>> {
        let byte = stdin.read_u8().await?;

        let verb = match byte {
            VERB_DELETE => Some(VimVerb::Delete),
            VERB_CHANGE => Some(VimVerb::Change),
            VERB_YANK => Some(VimVerb::Yank),
            _ => None,
        };
        let mut modifier = None;
        let motion;
        loop {
            let byte = if verb.is_some() || modifier.is_some() {
                stdin.read_u8().await?
            } else {
                byte
            };
            if is_modifier(&byte, &verb) {
                match byte {
                    b'a' => modifier = Some(Modifier::Around),
                    b'i' => modifier = Some(Modifier::Inner),
                    b if b.is_ascii_digit() && b != b'0' => {
                        // [TODO] fix this
                        if let Some(Modifier::Count(ref mut modifier)) = modifier {
                            *modifier =
                                (*modifier * 10) + (b.to_string().parse::<u16>().unwrap() - 48);
                        } else {
                            modifier =
                                Some(Modifier::Count(b.to_string().parse::<u16>().unwrap() - 48));
                        }
                    }
                    _ => {}
                }
            } else {
                use Motion::*;

                motion = Some(match byte {
                    b'h' => Left,
                    b'l' => Right,
                    b'k' => Up,
                    b'j' => Down,
                    b'0' => LineStart,
                    b'$' => LineEnd,
                    b'f' => {
                        let byte = stdin.read_u8().await?;
                        ToNextChar(byte as char)
                    }
                    b'F' => {
                        let byte = stdin.read_u8().await?;
                        ToPrevChar(byte as char)
                    }
                    b't' => {
                        let byte = stdin.read_u8().await?;
                        BeforeNextChar(byte as char)
                    }
                    b'T' => {
                        let byte = stdin.read_u8().await?;
                        BeforePrevChar(byte as char)
                    }
                    b'w' => NextWord,
                    b'b' => PrevWord,
                    b'e' => EndOfWord,
                    b => TextObject(b as char),
                });
                break;
            }
        }

        if (modifier == Some(Modifier::Around) || modifier == Some(Modifier::Inner))
            && !matches!(
                motion,
                Some(Motion::TextObject('(' | ')' | '[' | ']' | '<' | '>'))
            )
        {
            return Ok(None);
        }

        // Escape is pressed at any time, means we discard the command.
        if motion == Some(Motion::TextObject('\u{1b}')) {
            return Ok(None);
        }

        Ok(Some(VimCommand {
            verb,
            modifier,
            motion: motion.unwrap(),
        }))
    }
}

pub fn is_verb(byte: &u8) -> bool {
    VERBS.contains(byte)
}

pub fn is_modifier(byte: &u8, verb: &Option<VimVerb>) -> bool {
    (MODIFIERS.contains(byte) && verb.is_some()) || (byte.is_ascii_digit() && *byte != b'0')
}

pub fn get_matching_delimiters(c: char) -> Option<(char, char)> {
    match c {
        '(' | ')' => Some(('(' , ')')),
        '{' | '}' => Some(('{' , '}')),
        '<' | '>' => Some(('<' , '>')),
        _ => None
    }
}

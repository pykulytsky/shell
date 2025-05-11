#![allow(dead_code)]

use std::{iter::Peekable, str::Chars};

use crate::readline::constants::{DOUBLE_QUOTES_ESCAPE, GLOB};

#[derive(Debug)]
pub(crate) struct Tokenizer<'a> {
    it: Peekable<Chars<'a>>,
    in_single_quotes: bool,
    in_double_quotes: bool,
}

#[derive(Debug, PartialEq, PartialOrd)]
pub(crate) enum Token {
    Literal(String),
    Pipe,
    And,
    RightAngle,
    LeftAngle,
    LeftParen,
    RightParen,
    Dollar,
    NumberLiteral(u32),
    GlobPattern(String),
}

impl<'a> Tokenizer<'a> {
    pub fn new(it: &'a str) -> Self {
        Self {
            it: it.chars().peekable(),
            in_single_quotes: false,
            in_double_quotes: false,
        }
    }
}

impl Iterator for Tokenizer<'_> {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> {
        let mut current = String::new();

        while let Some(c) = self.it.next() {
            match c {
                '|' if !self.in_single_quotes && !self.in_double_quotes => {
                    return Some(Token::Pipe);
                }
                '&' if !self.in_single_quotes && !self.in_double_quotes => {
                    return Some(Token::And);
                }
                '$' if !self.in_single_quotes && !self.in_double_quotes => {
                    return Some(Token::Dollar);
                }
                '<' if !self.in_single_quotes && !self.in_double_quotes => {
                    return Some(Token::LeftAngle);
                }
                '>' if !self.in_single_quotes && !self.in_double_quotes => {
                    return Some(Token::RightAngle);
                }
                '(' if !self.in_single_quotes && !self.in_double_quotes => {
                    return Some(Token::LeftParen);
                }
                ')' if !self.in_single_quotes && !self.in_double_quotes => {
                    return Some(Token::RightParen);
                }
                c if c.is_ascii_digit() && (!self.in_single_quotes && !self.in_double_quotes) => {
                    return Some(Token::NumberLiteral(c.to_digit(10)?));
                }
                '\'' if !self.in_double_quotes => self.in_single_quotes = !self.in_single_quotes,
                '"' if !self.in_single_quotes => {
                    self.in_double_quotes = !self.in_double_quotes;
                }
                '\\' if self.in_double_quotes
                    || (!self.in_single_quotes && !self.in_double_quotes) =>
                {
                    if let Some(next_c) = self.it.next() {
                        if !self.in_double_quotes
                            || (self.in_double_quotes && DOUBLE_QUOTES_ESCAPE.contains(&next_c))
                        {
                            current.push(next_c);
                        } else {
                            current.push(c);
                            current.push(next_c);
                        }
                    }
                }
                ' ' if !self.in_single_quotes && !self.in_double_quotes => {
                    if !current.is_empty() {
                        if current.chars().any(|c| GLOB.contains(&c)) {
                            // let glob_list = glob::glob(current.as_str())
                            //     .into_iter()
                            //     .flatten()
                            //     .flatten()
                            //     .flat_map(|p| p.to_str().map(|s| s.to_string()));
                            return Some(Token::GlobPattern(current.clone()));
                        } else {
                            return Some(Token::Literal(current.clone()));
                        }
                    }
                }
                _ => current.push(c),
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let input = "cat *.rs | grep use";

        let tokenizer = Tokenizer::new(input);
        let tokens: Vec<Token> = tokenizer.collect();
        use Token::*;
        assert_eq!(
            tokens,
            vec![
                Literal("cat".to_string()),
                GlobPattern("*.rs".to_string()),
                Pipe,
                Literal("grep".to_string()),
                Literal("use".to_string())
            ]
        );
    }
}

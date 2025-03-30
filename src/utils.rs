#![allow(dead_code)]

pub const DOUBLE_QUOTES_ESCAPE: &[char] = &['$', '\\', '"'];

pub const REDIRECTS: &[&str] = &[">", "1>", "2>", ">>", "1>>", "2>>"];

pub fn trim_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    s.split_whitespace().for_each(|w| {
        dbg!(&w);
        if !result.is_empty() {
            result.push(' ');
        }
        result.push_str(w);
    });
    result
}

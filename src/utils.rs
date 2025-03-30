#![allow(dead_code)]

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

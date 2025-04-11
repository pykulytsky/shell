use std::collections::VecDeque;

use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use tokio::io::{self, AsyncReadExt};

use crate::{
    autocomplete::Trie,
    constants::{BUILTINS, HISTORY_FILE},
    Shell,
};

#[derive(Debug)]
pub struct Readline {
    pub prompt: Vec<u8>,
    pub prompt_cursor: usize,
    pub history: VecDeque<String>,
    pub history_cursor: Option<usize>,
    pub dictionary: Trie,
}

impl Readline {
    pub async fn new() -> Self {
        let path = std::env::var("PATH").unwrap_or_else(|_| "".to_string());
        let path_executables = Shell::populate_path_executables(&path).await;

        let mut dictionary = Trie::new();
        dictionary.extend(BUILTINS);
        for path in &path_executables {
            if let Some(p) = path.file_name().to_str() {
                dictionary.insert(p);
            }
        }

        let history = tokio::fs::read_to_string(HISTORY_FILE)
            .await
            .unwrap_or(String::new());

        Self {
            prompt: vec![],
            prompt_cursor: 0,
            history: history.lines().map(|l| l.to_string()).collect(),
            history_cursor: None,
            dictionary,
        }
    }

    pub async fn read(&mut self) -> io::Result<String> {
        enable_raw_mode()?;

        // code goes here

        disable_raw_mode()?;
        todo!()
    }
}

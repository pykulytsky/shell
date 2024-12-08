use std::process::exit;
use std::{fs::DirEntry, os::unix::fs::PermissionsExt};
pub mod command;

use command::Command;
use std::{
    fs::read_dir,
    io::{self, Write},
};

#[derive(Debug, Default)]
pub struct Shell {
    pub path: String,
    pub path_executables: Vec<DirEntry>,
}

impl Shell {
    pub fn new() -> Self {
        let path = std::env::var("PATH").unwrap_or("".to_string());
        let path_executables: Vec<DirEntry> = path
            .split(":")
            .flat_map(read_dir)
            .flatten()
            .flatten()
            .filter(|f| {
                let Ok(metadata) = f.metadata() else {
                    return false;
                };
                (metadata.is_file() || metadata.is_symlink())
                    && metadata.permissions().mode() & 0o111 != 0
            })
            .collect();
        Self {
            path,
            path_executables,
        }
    }

    pub fn start(&mut self) {
        let stdin = io::stdin();

        // Wait for user input
        let mut input = String::new();
        loop {
            print!("$ ");
            io::stdout().flush().unwrap();
            stdin.read_line(&mut input).unwrap();
            match Command::read(&input[..input.len() - 1]) {
                Ok(command) => self.run(command),
                Err(err) => eprintln!("{err}"),
            }
            input.clear();
        }
    }

    pub fn run(&self, command: Command) {
        match command {
            Command::Exit { status_code } => exit(status_code),
            Command::Echo { msg } => println!("{msg}"),
            Command::Type { command } => match command.as_ref() {
                c if matches!(c, "exit" | "echo" | "type") => println!("{c} is a shell builtin"),
                c if self
                    .path_executables
                    .iter()
                    .any(|e| e.path().components().last().unwrap().as_os_str() == c) =>
                {
                    let entry = self
                        .path_executables
                        .iter()
                        .find(|e| e.path().components().last().unwrap().as_os_str() == c)
                        .unwrap();
                    println!("{c} is {}", entry.path().as_path().to_string_lossy());
                }
                c => eprintln!("{c}: not found"),
            },
        }
    }
}

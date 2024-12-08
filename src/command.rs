use std::process::exit;

use thiserror::Error;

pub enum Command {
    Exit { status_code: i32 },
    Echo { msg: String },
    Type { command: String },
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("{0}: command not found")]
    InvalidCommand(String),

    #[error("Argument is not a number")]
    NotANumber(#[from] std::num::ParseIntError),
}

impl Command {
    pub fn read(input: &str) -> Result<Self, CommandError> {
        use Command::*;
        if let Some(rest) = input.strip_prefix("exit ") {
            Ok(Exit {
                status_code: rest.parse::<i32>()?,
            })
        } else if let Some(rest) = input.strip_prefix("echo ") {
            Ok(Echo {
                msg: rest.to_string(),
            })
        } else if let Some(rest) = input.strip_prefix("type ") {
            Ok(Type {
                command: rest.to_string(),
            })
        } else {
            Err(CommandError::InvalidCommand(input.to_string()))
        }
    }

    pub fn run(self) {
        match self {
            Command::Exit { status_code } => exit(status_code),
            Command::Echo { msg } => println!("{msg}"),
            Command::Type { command } => match command.as_ref() {
                "exit" | "echo" | "type" => println!("exit is a shell builtin"),
                c => eprintln!("{c}: not found"),
            },
        }
    }
}

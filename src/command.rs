use std::ffi::OsString;

use crate::Shell;
use thiserror::Error;

pub enum Command {
    Exit { status_code: i32 },
    Echo { msg: Vec<String> },
    Type { command: String },
    Pwd,
    Cd { path: String },
    Program { name: OsString, input: Vec<String> },
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("{0}: command not found")]
    InvalidCommand(String),

    #[error("Argument is not a number")]
    NotANumber(#[from] std::num::ParseIntError),
}

impl Command {
    pub fn read(input: &str, shell: &Shell) -> Result<Self, CommandError> {
        use Command::*;
        let args = Shell::parse_args(input);
        match args[0].as_str() {
            "exit" => Ok(Exit {
                status_code: args[1].parse::<i32>()?,
            }),
            "echo" => Ok(Echo {
                msg: args[1..].to_owned(),
            }),
            "type" => Ok(Type {
                command: args[1].to_string(),
            }),
            "pwd" => Ok(Pwd),
            "cd" => Ok(Cd {
                path: args[1].to_string(),
            }),
            arg if shell.get_path_executable(arg).is_some() => Ok(Program {
                name: shell
                    .get_path_executable(arg)
                    .unwrap()
                    .path()
                    .into_os_string(),
                input: args[1..].to_owned(),
            }),
            arg => Err(CommandError::InvalidCommand(arg.to_string())),
        }
    }
}

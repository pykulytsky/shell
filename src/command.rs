use std::ffi::OsString;
use tokio::{
    fs::{File, OpenOptions},
    io::{stderr, stdout, AsyncWrite},
};

use crate::{utils::REDIRECTS, Shell};
use thiserror::Error;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Sink {
    Stdout,
    Stderr,
    StdoutAppend,
    StderrAppend,
}

#[derive(Debug)]
pub enum CommandKind {
    Exit { status_code: i32 },
    Echo { msg: Vec<String> },
    Type { arg: String },
    Pwd,
    Cd { path: String },
    ExternalCommand { name: OsString, input: Vec<String> },
    History,
}

pub struct Command {
    pub kind: CommandKind,
    pub out: Box<dyn AsyncWrite + Unpin>,
    pub err: Box<dyn AsyncWrite + Unpin>,
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("{0}: command not found")]
    InvalidCommand(String),

    #[error("Argument is not a number")]
    NotANumber(#[from] std::num::ParseIntError),
}

impl Command {
    pub async fn read(input: &str, shell: &Shell) -> Result<Command, CommandError> {
        use CommandKind::*;
        let mut args = Shell::parse_args(input);

        let redirect_pos = args.iter().position(|a| REDIRECTS.contains(&a.as_str()));
        let redirect_to = redirect_pos.map(|pos| args[pos + 1].clone());
        let sink = redirect_pos.map(|pos| match args[pos].as_str() {
            ">" | "1>" => Sink::Stdout,
            ">>" | "1>>" => Sink::StdoutAppend,
            "2>" => Sink::Stderr,
            "2>>" => Sink::StderrAppend,
            _ => todo!(),
        });

        // redirect can not be last argument
        if let Some(redirect_pos) = redirect_pos {
            if redirect_pos == args.len() - 1 || redirect_pos < args.len() - 2 {
                return Err(CommandError::InvalidCommand("Can not redirect".to_string()));
            }
            args.pop(); // remove destination
            args.pop(); // remove sink
        }

        let kind = match args[0].as_str() {
            "exit" => Ok(Exit {
                status_code: match args.get(1) {
                    Some(status_code) => status_code.parse::<i32>()?,
                    None => 0,
                },
            }),
            "echo" => Ok(Echo {
                msg: args[1..].to_owned(),
            }),
            "type" => Ok(Type {
                arg: args[1].to_string(),
            }),
            "pwd" => Ok(Pwd),
            "cd" => Ok(Cd {
                path: args[1].to_string(),
            }),
            "history" => Ok(History),
            arg if shell.get_path_executable(arg).is_some() => Ok(ExternalCommand {
                name: shell
                    .get_path_executable(arg)
                    .unwrap()
                    .path()
                    .into_os_string(),
                input: args[1..].to_owned(),
            }),
            arg => Err(CommandError::InvalidCommand(arg.to_string())),
        };

        match (redirect_to, sink) {
            (Some(to), Some(Sink::Stdout | Sink::StdoutAppend)) => Ok(Command {
                kind: kind?,
                out: Box::new(open_redirect_file(to, sink.unwrap() == Sink::StdoutAppend).await),
                err: Box::new(stderr()),
            }),
            (Some(to), Some(Sink::Stderr | Sink::StderrAppend)) => Ok(Command {
                kind: kind?,
                out: Box::new(stdout()),
                err: Box::new(open_redirect_file(to, sink.unwrap() == Sink::StderrAppend).await),
            }),
            _ => Ok(Command {
                kind: kind?,
                out: Box::new(stdout()),
                err: Box::new(stderr()),
            }),
        }
    }
}

async fn open_redirect_file(to: String, append: bool) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(append)
        .truncate(!append)
        .open(to)
        .await
        .unwrap()
}

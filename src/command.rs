use std::ffi::OsString;

use crate::{readline::constants::REDIRECTS, Shell};
use thiserror::Error;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Sink {
    Stdout,
    Stderr,
    StdoutAppend,
    StderrAppend,
}

impl Sink {
    pub fn is_append(&self) -> bool {
        match self {
            Sink::Stdout => false,
            Sink::Stderr => false,
            Sink::StdoutAppend => true,
            Sink::StderrAppend => true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum CommandKind {
    Exit { status_code: i32 },
    Cd { path: String },
    ExternalCommand { name: OsString, input: Vec<String> },
    History,
}

#[derive(Debug, Clone)]
pub struct Command {
    pub kind: CommandKind,
    pub stdout_redirect: Option<String>,
    pub stderr_redirect: Option<String>,
    pub sink: Option<Sink>,
    pub pipe_to: Option<Box<Command>>,
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("{0}: command not found")]
    InvalidCommand(String),

    #[error("Argument is not a number")]
    NotANumber(#[from] std::num::ParseIntError),
}

impl Command {
    pub async fn parse(input: &str, shell: &Shell) -> Result<Command, CommandError> {
        let args = Shell::parse_prompt(input);
        let subcommand_strs = args.split(|a| a == "|");

        let mut commands = vec![];

        for subcommand_str in subcommand_strs {
            commands.push(Self::read(subcommand_str.to_vec(), shell).await?);
        }

        let command = commands.into_iter().reduce(|mut acc, next| {
            acc.pipe_to = Some(Box::new(next));
            acc
        });

        Ok(command.unwrap())
    }

    pub async fn read(mut args: Vec<String>, shell: &Shell) -> Result<Command, CommandError> {
        use CommandKind::*;

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
            "exit" => Exit {
                status_code: match args.get(1) {
                    Some(status_code) => status_code.parse::<i32>()?,
                    None => 0,
                },
            },
            "cd" => Cd {
                path: args[1].to_string(),
            },
            "history" => History,
            arg => ExternalCommand {
                name: shell
                    .get_path_executable(arg)
                    .await
                    .ok_or(CommandError::InvalidCommand(arg.to_string()))?
                    .path()
                    .into_os_string(),
                input: args[1..].to_owned(),
            },
        };

        match (redirect_to, sink) {
            (Some(to), Some(Sink::Stdout | Sink::StdoutAppend)) => Ok(Command {
                kind,
                stdout_redirect: Some(to),
                stderr_redirect: None,
                sink,
                pipe_to: None,
            }),
            (Some(to), Some(Sink::Stderr | Sink::StderrAppend)) => Ok(Command {
                kind,
                stdout_redirect: None,
                stderr_redirect: Some(to),
                sink,
                pipe_to: None,
            }),
            _ => Ok(Command {
                kind,
                stdout_redirect: None,
                stderr_redirect: None,
                sink,
                pipe_to: None,
            }),
        }
    }
}

use std::os::unix::process::ExitStatusExt;
use std::{ffi::OsString, process::ExitStatus};
use tokio::io::{stderr, stdout, AsyncWriteExt};

use crate::utils::open_file_async;
use crate::{parse_prompt, readline::constants::REDIRECTS};
use thiserror::Error;
use tokio::io::AsyncWrite;

#[derive(Debug, PartialEq, Clone, Copy, PartialOrd)]
pub enum SinkKind {
    Stdout,
    Stderr,
    StdoutAppend,
    StderrAppend,
}

impl SinkKind {
    pub fn is_append(&self) -> bool {
        match self {
            SinkKind::Stdout => false,
            SinkKind::Stderr => false,
            SinkKind::StdoutAppend => true,
            SinkKind::StderrAppend => true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Builtin {
    Exit { status_code: i32 },
    Cd { path: String },
    History,
    Jobs,
    Fg(Option<u32>),
}

impl Builtin {
    pub async fn execute(
        self,
        shell: &mut crate::Shell,
        command: Command,
    ) -> tokio::io::Result<()> {
        let mut out: &mut (dyn AsyncWrite + Unpin) = match command.stdout_redirect {
            Some(ref out) => {
                &mut open_file_async(out, command.sink.map(|s| s.is_append()).unwrap_or(false))
                    .await?
            }
            None => &mut stdout(),
        };
        let err: &mut (dyn AsyncWrite + Unpin) = match command.stderr_redirect {
            Some(ref err) => {
                &mut open_file_async(err, command.sink.map(|s| s.is_append()).unwrap_or(false))
                    .await?
            }

            None => &mut stderr(),
        };
        match self {
            Builtin::Exit { status_code } => {
                shell
                    .handle_exit(Some(ExitStatus::from_raw(status_code)))
                    .await
            }
            Builtin::Cd { path } => {
                let home = std::env::var("HOME").unwrap();
                let mut cd_path = path.clone();

                if path == "~" {
                    cd_path = home;
                }

                if std::env::set_current_dir(&cd_path).is_err() {
                    err.write_all(format!("cd: {path}: No such file or directory\r\n").as_bytes())
                        .await?;
                }

                Ok(())
            }
            Builtin::History => shell.dump_history(&mut out).await,
            Builtin::Jobs => shell.show_jobs(&mut out).await,
            Builtin::Fg(pid) => shell.move_job_to_foreground(pid).await,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExternalCommand {
    pub name: OsString,
    pub args: Vec<String>,
    pub stdout_redirect: Option<String>,
    pub stderr_redirect: Option<String>,
    pub sink: Option<SinkKind>,
    pub pipe_to: Option<Box<Command>>,
    pub is_bg_job: bool,
}

impl TryFrom<Command> for ExternalCommand {
    type Error = CommandError;
    fn try_from(command: Command) -> Result<Self, Self::Error> {
        if let CommandKind::External { name, args } = command.kind {
            Ok(Self {
                name,
                args,
                stdout_redirect: command.stdout_redirect,
                stderr_redirect: command.stderr_redirect,
                sink: command.sink,
                pipe_to: command.pipe_to,
                is_bg_job: command.is_bg_job,
            })
        } else {
            Err(CommandError::InvalidCommand(
                "not an external commmand".to_owned(),
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub enum CommandKind {
    External { name: OsString, args: Vec<String> },
    Builtin(Builtin),
}

impl Default for CommandKind {
    fn default() -> Self {
        Self::Builtin(Builtin::Exit { status_code: 0 })
    }
}

#[derive(Debug, Clone, Default)]
pub struct Command {
    pub kind: CommandKind,
    pub stdout_redirect: Option<String>,
    pub stderr_redirect: Option<String>,
    pub sink: Option<SinkKind>,
    pub pipe_to: Option<Box<Command>>,
    pub is_bg_job: bool,
}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("{0}: command not found")]
    InvalidCommand(String),

    #[error("Argument is not a number")]
    NotANumber(#[from] std::num::ParseIntError),
}

impl Command {
    pub async fn parse(input: &str) -> Result<Command, CommandError> {
        let args = parse_prompt(input);

        let subcommand_strs = args.split(|a| a == "|");
        let mut commands = vec![];

        for subcommand_str in subcommand_strs {
            commands.push(Self::read(subcommand_str.to_vec()).await?);
        }

        let mut iter = commands.into_iter().rev();
        let mut command = iter.next().unwrap();

        for mut prev in iter {
            prev.pipe_to = Some(Box::new(command));
            command = prev;
        }

        Ok(command)
    }

    pub async fn read(mut args: Vec<String>) -> Result<Command, CommandError> {
        use Builtin::*;

        let redirect_pos = args.iter().position(|a| REDIRECTS.contains(&a.as_str()));
        let redirect_to = redirect_pos.map(|pos| args[pos + 1].clone());
        let sink = redirect_pos.map(|pos| match args[pos].as_str() {
            ">" | "1>" => SinkKind::Stdout,
            ">>" | "1>>" => SinkKind::StdoutAppend,
            "2>" => SinkKind::Stderr,
            "2>>" => SinkKind::StderrAppend,
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

        let mut is_bg_job = false;

        if let Some(last) = args.last() {
            if last == "&" {
                is_bg_job = true;
                args.pop();
            }
        }

        let kind = match args[0].as_str() {
            "exit" => CommandKind::Builtin(Exit {
                status_code: match args.get(1) {
                    Some(status_code) => status_code.parse::<i32>()?,
                    None => 0,
                },
            }),
            "cd" => CommandKind::Builtin(Cd {
                path: args[1].to_string(),
            }),
            "history" => CommandKind::Builtin(History),
            "jobs" => CommandKind::Builtin(Jobs),
            "fg" => CommandKind::Builtin(Fg(args.get(1).map(|pid| pid.parse().unwrap()))),
            arg => {
                let name = OsString::from(arg);

                CommandKind::External {
                    name,
                    args: args[1..].to_owned(),
                }
            }
        };

        match (redirect_to, sink) {
            (Some(to), Some(SinkKind::Stdout | SinkKind::StdoutAppend)) => Ok(Command {
                kind,
                stdout_redirect: Some(to),
                sink,
                is_bg_job,
                ..Default::default()
            }),
            (Some(to), Some(SinkKind::Stderr | SinkKind::StderrAppend)) => Ok(Command {
                kind,
                stderr_redirect: Some(to),
                sink,
                is_bg_job,
                ..Default::default()
            }),
            _ => Ok(Command {
                kind,
                sink,
                is_bg_job,
                ..Default::default()
            }),
        }
    }
}

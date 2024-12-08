use thiserror::Error;

pub enum Command {}

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("{0}: command not found")]
    InvalidCommand(String),
}

impl Command {
    pub fn read(input: &str) -> Result<Self, CommandError> {
        Err(CommandError::InvalidCommand(input.to_string()))
    }
}
